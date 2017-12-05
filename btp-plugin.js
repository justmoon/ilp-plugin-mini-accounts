'use strict'

const crypto = require('crypto')
const debug = require('debug')('ilp-plugin-mini-accounts:btp-plugin')
const EventEmitter = require('events').EventEmitter
const BtpPacket = require('btp-packet')
const IlpPacket = require('ilp-packet')
const base64url = require('base64url')

const { protocolDataToIlpAndCustom, ilpAndCustomToProtocolData } =
  require('./protocol-data-converter')

const errors = require('./errors')
const MissingFulfillmentError = errors.MissingFulfillmentError
const NotAcceptedError = errors.NotAcceptedError
const InvalidFieldsError = errors.InvalidFieldsError
const AlreadyRolledBackError = errors.AlreadyRolledBackError
const RequestHandlerAlreadyRegisteredError = errors.RequestHandlerAlreadyRegisteredError

const int64 = require('./int64')

const DEFAULT_TIMEOUT = 5000
const namesToCodes = {
  'UnreachableError': 'T00',
  'NotAcceptedError': 'F00',
  'InvalidFieldsError': 'F01',
  'TransferNotFoundError': 'F02',
  'InvalidFulfillmentError': 'F03',
  'DuplicateIdError': 'F04',
  'AlreadyRolledBackError': 'F05',
  'AlreadyFulfilledError': 'F06',
  'InsufficientBalanceError': 'F07'
}

function jsErrorToBtpError (e) {
  const name = e.name || 'NotAcceptedError'
  const code = namesToCodes[name] || 'F00'

  return {
    code,
    name,
    triggeredAt: new Date(),
    data: JSON.stringify({ message: e.message })
  }
}

const INFO_REQUEST_ACCOUNT = 0 // eslint-disable-line no-unused-vars
const INFO_REQUEST_FULL = 2

/**
 * Abstract base class for building BTP-based ledger plugins.
 *
 * This class takes care of most of the work translating between BTP and the
 * ledger plugin interface (LPI).
 *
 * You need to implement:
 *
 * connect()
 * disconnect()
 * isConnected()
 * getInfo()
 * getAccount()
 * getBalance()
 *
 * This class takes care of:
 *
 * getFulfillment()
 * sendTransfer()
 * sendRequest()
 * fulfillCondition()
 * rejectIncomingTransfer()
 * registerRequestHandler()
 * deregisterRequestHandler()
 *
 * Instead, you need to implement _handleOutgoingBtpPacket(to, btpPacket) which
 * returns a Promise. `to` is the ILP address of the destination peer and
 * `btpPacket` is the BTP packet as a JavaScript object.
 *
 * You can call _handleIncomingBtpPacket(from, btpPacket) to trigger all the
 * necessary LPI events in response to an incoming BTP packet. `from` is the ILP
 * address of the peer and `btpPacket` is the parsed BTP packet.
 */
class AbstractBtpPlugin extends EventEmitter {
  constructor () {
    super()

    this._requestHandler = null

    // TODO: Should clean up expired transfers from these maps
    this._incomingTransfers = new Map()
    this._outgoingTransfers = new Map()
  }

  // don't throw errors even if the event handler throws
  // this is especially important in plugins because
  // errors can prevent the balance from being updated correctly
  _safeEmit () {
    try {
      this.emit.apply(this, arguments)
    } catch (err) {
      const errInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
      debug('error in handler for event', arguments, errInfo)
    }
  }

  async getFulfillment (transferId) {
    // We don't store transfers past their execution, so we will never have a
    // fulfillment for an already executed transfer.
    throw new MissingFulfillmentError()
  }

  async _call (to, btpPacket) {
    const requestId = btpPacket.requestId

    debug('sending ', btpPacket)

    let callback
    const response = new Promise((resolve, reject) => {
      callback = (type, data) => {
        switch (type) {
          case BtpPacket.TYPE_RESPONSE:
            resolve(data)
            break

          case BtpPacket.TYPE_ERROR:
            reject(new Error(JSON.stringify(data)))
            break

          default:
            throw new Error('Unkown BTP packet type', data)
        }
      }
      this.once('__callback_' + requestId, callback)
    })

    await this._handleOutgoingBtpPacket(to, btpPacket)

    const timeout = new Promise((resolve, reject) =>
      setTimeout(() => {
        this.removeListener('__callback_' + requestId, callback)
        reject(new Error(requestId + ' timed out'))
      }, DEFAULT_TIMEOUT))

    return Promise.race([
      response,
      timeout
    ])
  }

  async _handleIncomingBtpPacket (from, btpPacket) {
    const {type, requestId, data} = btpPacket
    const typeString = BtpPacket.typeToString(type)

    debug(`received BTP packet (${typeString}, RequestId: ${requestId}): ${JSON.stringify(data)}`)

    try {
      let result
      switch (type) {
        case BtpPacket.TYPE_RESPONSE:
        case BtpPacket.TYPE_ERROR:
          this.emit('__callback_' + requestId, type, data)
          return
        case BtpPacket.TYPE_PREPARE:
          result = await this._handleTransfer(from, btpPacket)
          break
        case BtpPacket.TYPE_FULFILL:
          result = await this._handleFulfillCondition(from, btpPacket)
          break
        case BtpPacket.TYPE_REJECT:
          result = await this._handleRejectIncomingTransfer(from, btpPacket)
          break
        case BtpPacket.TYPE_MESSAGE:
          result = await this._handleRequest(from, btpPacket)
          break
      }

      debug(`replying to request ${requestId} with ${JSON.stringify(result)}`)
      await this._handleOutgoingBtpPacket(from, {
        type: BtpPacket.TYPE_RESPONSE,
        requestId,
        data: { protocolData: result || [] }
      })
    } catch (e) {
      debug(`Error processing BTP packet of type ${typeString}: `, e)
      const error = jsErrorToBtpError(e)

      const { code, name, triggeredAt, data } = error

      await this._handleOutgoingBtpPacket(from, {
        type: BtpPacket.TYPE_ERROR,
        requestId,
        data: {
          code,
          name,
          triggeredAt,
          data,
          protocolData: []
        }
      })
      throw e
    }
  }

  async sendTransfer (transfer) {
    const {id, amount, executionCondition, expiresAt} = transfer
    const protocolData = ilpAndCustomToProtocolData(transfer)
    const requestId = await _requestId()

    this._outgoingTransfers.set(transfer.id, transfer)

    this._safeEmit('outgoing_prepare', transfer)

    await this._call(transfer.to, {
      type: BtpPacket.TYPE_PREPARE,
      requestId,
      data: {
        transferId: id,
        amount,
        executionCondition,
        expiresAt,
        protocolData
      }
    })

    return null
  }

  async _handleTransfer (from, { data }) {
    const { ilp, custom } = protocolDataToIlpAndCustom(data)
    const transfer = {
      id: data.transferId,
      amount: data.amount,
      executionCondition: data.executionCondition,
      expiresAt: data.expiresAt.toISOString(),
      to: this.getAccount(),
      from,
      ledger: this._prefix
    }

    if (ilp) transfer.ilp = ilp
    if (custom) transfer.custom = custom

    this._incomingTransfers.set(transfer.id, transfer)

    this._safeEmit('incoming_prepare', transfer)
  }

  async sendRequest (message) {
    const protocolData = ilpAndCustomToProtocolData(message)
    const requestId = await _requestId()

    this._safeEmit('outgoing_request', message)

    const btpResponse = await this._call(message.to, {
      type: BtpPacket.TYPE_MESSAGE,
      requestId,
      data: { protocolData }
    })

    const { ilp, custom } = protocolDataToIlpAndCustom(btpResponse)

    const parsed = {
      to: message.from,
      from: message.to,
      ledger: this.getInfo().prefix
    }

    if (ilp) parsed.ilp = ilp
    if (custom) parsed.custom = custom

    this._safeEmit('incoming_response', parsed)

    return parsed
  }

  async _handleRequest (from, {requestId, data}) {
    const { ilp, custom, protocolMap } = protocolDataToIlpAndCustom(data)
    const message = {
      id: requestId,
      to: this.getAccount(),
      from
    }

    if (ilp) message.ilp = ilp
    if (custom) message.custom = custom

    // if there are side protocols only
    if (!ilp) {
      if (protocolMap.info) {
        if (Buffer.isBuffer(protocolMap.info) &&
            protocolMap.info.readInt8() === INFO_REQUEST_FULL) {
          // We need to trick each client into thinking that they are on their
          // own separate subledger to force them to use a connector.
          //
          // Otherwise, they will try to deliver locally to each other which
          // may not work since we are actually routing all payments through
          // the parent connector.
          //
          // This wouldn't be necessary if we got rid of the distinction
          // between forwarding and delivery.
          const info = Object.assign({}, this.getInfo())
          info.prefix = from + '.'
          info.connectors = [ from + '.server' ]

          return [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_APPLICATION_JSON,
            data: Buffer.from(JSON.stringify(info))
          }]
        } else {
          return [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
            data: Buffer.from(this.getAccount())
          }]
        }
      } else if (protocolMap.balance) {
        return [{
          protocolName: 'balance',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: int64.toBuffer(await this._handleGetBalance())
        }]
      } else if (protocolMap.limit) {
        return [{
          protocolName: 'limit',
          contentType: BtpPacket.MIME_APPLICATION_JSON,
          data: Buffer.from(JSON.stringify(await this._handleGetLimit()))
        }]
      } else if (protocolMap.custom) {
        // Don't throw -- this message will be emitted.
      } else {
        if (this._paychanContext.rpc.handleProtocols) {
          return this._paychanContext.rpc.handleProtocols(protocolMap)
        } else {
          throw new Error('Unsupported side protocol.')
        }
      }
    }

    this._safeEmit('incoming_request', message)

    if (!this._requestHandler) {
      throw new NotAcceptedError('no request handler registered')
    }

    const response = await this._requestHandler(message)
      .catch((e) => ({
        ledger: message.ledger,
        to: from,
        from: this.getAccount(),
        ilp: base64url(IlpPacket.serializeIlpError({
          code: 'F00',
          name: 'Bad Request',
          triggeredBy: this.getAccount(),
          forwardedBy: [],
          triggeredAt: new Date(),
          data: JSON.stringify({ message: e.message })
        }))
      }))

    this._safeEmit('outgoing_response', response)

    return ilpAndCustomToProtocolData({ ilp: response.ilp, custom: response.custom })
  }

  async fulfillCondition (transferId, fulfillment, ilp) {
    const protocolData = ilp
      ? [{ protocolName: 'ilp', contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM, data: ilp }]
      : []
    const requestId = await _requestId()

    const transfer = this._getIncomingTransferById(transferId)

    if (new Date(transfer.expiresAt).getTime() < Date.now()) {
      throw new AlreadyRolledBackError(transferId + ' has already expired: ' +
        JSON.stringify(transfer))
    }

    this._safeEmit('incoming_fulfill', transfer, fulfillment, ilp)

    await this._call(transfer.from, {
      type: BtpPacket.TYPE_FULFILL,
      requestId,
      data: {
        transferId,
        fulfillment,
        protocolData
      }
    })

    this._incomingTransfers.delete(transferId)

    return null
  }

  async _handleFulfillCondition (from, { data }) {
    const transferId = data.transferId
    const { ilp } = protocolDataToIlpAndCustom(data)
    const transfer = this._getOutgoingTransferById(transferId)

    this._safeEmit('outgoing_fulfill', transfer, data.fulfillment, ilp)

    this._outgoingTransfers.delete(transferId)

    return []
  }

  async rejectIncomingTransfer (transferId, reason) {
    const transfer = this._getIncomingTransferById(transferId)
    const requestId = await _requestId()
    // reason.forwarded_by should be a string according to LPIv1
    // but we might as well accept an array also since the ILP error
    // expects an array
    let forwardedBy
    if (Array.isArray(reason.forwarded_by)) {
      forwardedBy = reason.forwarded_by
    } else if (typeof reason.forwarded_by === 'string') {
      forwardedBy = [reason.forwarded_by]
    } else {
      forwardedBy = []
    }
    const rejectionReason = IlpPacket.serializeIlpError({
      code: reason.code,
      name: reason.name,
      message: reason.message,
      triggeredBy: reason.triggered_by || '',
      forwardedBy,
      triggeredAt: (reason.triggered_at && new Date(reason.triggered_at)) || new Date(),
      data: (reason.additional_info && JSON.stringify(reason.additional_info)) || ''
    })
    const protocolData = [{
      protocolName: 'ilp',
      contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
      data: rejectionReason
    }]

    this._safeEmit('incoming_reject', transfer, reason)

    await this._call(transfer.from, {
      type: BtpPacket.TYPE_REJECT,
      requestId,
      data: {
        transferId,
        protocolData
      }
    })

    this._incomingTransfers.delete(transferId)

    return null
  }

  async _handleRejectIncomingTransfer (from, { data }) {
    const { ilp } = protocolDataToIlpAndCustom(data)
    const ilpPacket = IlpPacket.deserializeIlpPacket(Buffer.from(ilp, 'base64')).data

    const rejectionReason = {
      code: ilpPacket.code,
      name: ilpPacket.name,
      message: ilpPacket.message,
      triggered_by: ilpPacket.triggeredBy,
      forwarded_by: ilpPacket.forwardedBy,
      triggered_at: ilpPacket.triggeredAt,
      additional_info: ilpPacket.data
    }

    this._safeEmit('outgoing_reject', this._getOutgoingTransferById(data.transferId), rejectionReason)

    this._outgoingTransfers.delete(data.id)
  }

  // TODO: This function should be deprecated from RFC-0004. Instead we should
  // use registerSideProtocolHandler. (@sharafian)
  registerRequestHandler (handler) {
    if (this._requestHandler) {
      throw new RequestHandlerAlreadyRegisteredError('requestHandler is already registered')
    }

    if (typeof handler !== 'function') {
      throw new InvalidFieldsError('requestHandler must be a function')
    }

    debug('registering request handler')
    this._requestHandler = handler
  }

  deregisterRequestHandler () {
    this._requestHandler = null
  }

  _getIncomingTransferById (transferId) {
    const transfer = this._incomingTransfers.get(transferId)

    if (transfer) {
      return transfer
    } else {
      throw new Error('Unrecognized incoming transfer id ' + transferId)
    }
  }

  _getOutgoingTransferById (transferId) {
    const transfer = this._outgoingTransfers.get(transferId)

    if (transfer) {
      return transfer
    } else {
      throw new Error('Unrecognized outgoing transfer id ' + transferId)
    }
  }
}

async function _requestId () {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(4, (err, buf) => {
      if (err) reject(err)
      resolve(buf.readUInt32BE(0))
    })
  })
}

module.exports = AbstractBtpPlugin
