const crypto = require('crypto')
const BtpPacket = require('btp-packet')
const BigNumber = require('bignumber.js')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-mini-accounts')
const AbstractBtpPlugin = require('./btp-plugin')
const base64url = require('base64url')

function tokenToAccount (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

function ilpAddressToAccount (prefix, ilpAddress) {
  if (ilpAddress.substr(0, prefix.length) !== prefix) {
    throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + prefix + ')')
  }

  return ilpAddress.substr(prefix.length).split('.')[0]
}

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super()
    this._prefix = opts.prefix
    this._port = opts.port || 3000
    this._wsOpts = opts.wsOpts || { port: this._port }
    this._currencyScale = opts.currencyScale || 9
    this._modeInfiniteBalances = !!opts.debugInfiniteBalances

    this._log = opts._log || console
    this._wss = null
    this._balances = new Map()
    this._connections = new Map()

    this.on('outgoing_fulfill', this._handleOutgoingFulfill.bind(this))
    this.on('incoming_reject', this._handleIncomingReject.bind(this))

    if (this._modeInfiniteBalances) {
      this._log.warn('(!!!) granting all users infinite balances')
    }
  }

  connect () {
    if (this._wss) return

    debug('listening on port ' + this._port)
    const wss = this._wss = new WebSocket.Server(this._wsOpts)
    wss.on('connection', (wsIncoming) => {
      debug('got connection')
      let token
      let account

      // The first message must be an auth packet
      // with the macaroon as the auth_token
      let authPacket
      wsIncoming.once('message', (binaryAuthMessage) => {
        try {
          authPacket = BtpPacket.deserialize(binaryAuthMessage)
          assert.equal(authPacket.type, BtpPacket.TYPE_MESSAGE, 'First message sent over BTP connection must be auth packet')
          assert(authPacket.data.protocolData.length >= 2, 'Auth packet must have auth and auth_token subprotocols')
          assert.equal(authPacket.data.protocolData[0].protocolName, 'auth', 'First subprotocol must be auth')
          for (let subProtocol of authPacket.data.protocolData) {
            if (subProtocol.protocolName === 'auth_token') {
              // TODO: Do some validation on the token
              token = subProtocol.data
              account = tokenToAccount(token)

              let connections = this._connections.get(account)
              if (!connections) {
                this._connections.set(account, connections = new Set())
              }

              connections.add(wsIncoming)
            }
          }
          assert(token, 'auth_token subprotocol is required')

          wsIncoming.send(BtpPacket.serializeResponse(authPacket.requestId, []))
        } catch (err) {
          if (authPacket) {
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              data: err.message,
              triggeredAt: new Date().toISOString()
            }, authPacket.requestId, [])
            wsIncoming.send(errorResponse)
          }
          wsIncoming.close()
          return
        }

        debug('connection authenticated')

        wsIncoming.on('message', (binaryMessage) => {
          let btpPacket
          try {
            btpPacket = BtpPacket.deserialize(binaryMessage)
          } catch (err) {
            wsIncoming.close()
          }
          debug(`account ${account}: processing btp packet ${JSON.stringify(btpPacket)}`)
          try {
            if (btpPacket.type === BtpPacket.TYPE_PREPARE) {
              this._handleIncomingBtpPrepare(account, btpPacket)
            }
            debug('packet is authorized, forwarding to host')
            this._handleIncomingBtpPacket(this._prefix + account, btpPacket)
          } catch (err) {
            debug('btp packet not accepted', err)
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              triggeredAt: new Date().toISOString(),
              data: err.message
            }, btpPacket.requestId, [])
            wsIncoming.send(errorResponse)
          }
        })
      })
    })

    return null
  }

  disconnect () {
    if (this._wss) {
      return new Promise(resolve => {
        this._wss.close(resolve)
        this._wss = null
      })
    }
  }

  isConnected () {
    return !!this._wss
  }

  _handleIncomingBtpPrepare (account, btpPacket) {
    const prepare = btpPacket.data
    if (prepare.protocolData.length < 1 || prepare.protocolData[0].protocolName !== 'ilp') {
      throw new Error('ILP packet is required')
    }
    // const ilp = IlpPacket.deserializeIlpPayment(prepare.protocolData[0].data)

    const currentBalance = this._balances.get(account) || new BigNumber(0)

    const newBalance = currentBalance.sub(prepare.amount)

    if (newBalance.lessThan(0) && !this._modeInfiniteBalances) {
      throw new Error('Insufficient funds, have: ' + currentBalance + ' need: ' + prepare.amount)
    }

    this._balances.set(account, newBalance)

    debug(`account ${account} debited ${prepare.amount} units, new balance ${newBalance}`)
  }

  _handleOutgoingFulfill (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.to)
    const currentBalance = this._balances.get(account) || new BigNumber(0)
    const newBalance = currentBalance.add(transfer.amount)

    this._balances.set(account, newBalance)

    debug(`account ${account} credited ${transfer.amount} units, new balance ${newBalance}`)
  }

  _handleIncomingReject (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)
    const currentBalance = this._balances.get(account) || new BigNumber(0)
    const newBalance = currentBalance.add(transfer.amount)

    this._balances.set(account, newBalance)

    debug(`account ${account} credited ${transfer.amount} units, new balance ${newBalance}`)
  }

  getAccount () {
    return this._prefix + 'server'
  }

  getInfo () {
    return {
      prefix: this._prefix,
      connectors: [],
      currencyScale: this._currencyScale
    }
  }

  async _handleOutgoingBtpPacket (to, btpPacket) {
    if (to.substring(0, this._prefix.length) !== this._prefix) {
      throw new Error('Invalid destination "' + to + '", must start with prefix: ' + this._prefix)
    }

    const account = ilpAddressToAccount(this._prefix, to)

    const connections = this._connections.get(account)

    if (!connections) {
      throw new Error('No clients connected for account ' + account)
    }

    const results = Array.from(connections).map(wsIncoming => {
      const result = new Promise(resolve => wsIncoming.send(BtpPacket.serialize(btpPacket), resolve))

      result.catch(err => {
        const errorInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
        debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
      })
    })

    await Promise.all(results)

    return null
  }
}

module.exports = Plugin
