const crypto = require('crypto')
const BtpPacket = require('btp-packet')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-mini-accounts')
const AbstractBtpPlugin = require('ilp-plugin-btp')
const base64url = require('base64url')
const ILDCP = require('ilp-protocol-ildcp')
const IlpPacket = require('ilp-packet')

function tokenToAccount (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super({})
    const defaultPort = opts.port || 3000
    this._wsOpts = opts.wsOpts || { port: defaultPort }
    this._currencyScale = opts.currencyScale || 9
    this._debugHostIldcpInfo = opts.debugHostIldcpInfo

    this._log = opts._log || console
    this._wss = null
    this._connections = new Map()
  }

  ilpAddressToAccount (ilpAddress) {
    if (ilpAddress.substr(0, this._prefix.length) !== this._prefix) {
      throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + this._prefix + ')')
    }

    return ilpAddress.substr(this._prefix.length).split('.')[0]
  }

  async connect () {
    if (this._wss) return

    this._hostIldcpInfo = this._debugHostIldcpInfo || await ILDCP.fetch(this._dataHandler.bind(this))
    this._prefix = this._hostIldcpInfo.clientAddress + '.'

    if (this._preConnect) {
      await this._preConnect()
    }

    debug('listening on port ' + this._wsOpts.port)
    const wss = this._wss = new WebSocket.Server(this._wsOpts)
    wss.on('connection', (wsIncoming, req) => {
      debug('got connection')
      let token
      let account

      // The first message must be an auth packet
      // with the macaroon as the auth_token
      let authPacket
      wsIncoming.once('message', async (binaryAuthMessage) => {
        try {
          authPacket = BtpPacket.deserialize(binaryAuthMessage)
          assert.equal(authPacket.type, BtpPacket.TYPE_MESSAGE, 'First message sent over BTP connection must be auth packet')
          assert(authPacket.data.protocolData.length >= 2, 'Auth packet must have auth and auth_token subprotocols')
          assert.equal(authPacket.data.protocolData[0].protocolName, 'auth', 'First subprotocol must be auth')
          for (let subProtocol of authPacket.data.protocolData) {
            if (subProtocol.protocolName === 'auth_token') {
              // TODO: Do some validation on the token
              token = subProtocol.data.toString()
              account = account || tokenToAccount(token)

              let connections = this._connections.get(account)
              if (!connections) {
                this._connections.set(account, connections = new Set())
              }

              connections.add(wsIncoming)
            } else if (subProtocol.protocolName === 'auth_username') {
              account = subProtocol.data.toString()
            }
          }
          assert(token, 'auth_token subprotocol is required')

          debug('got auth info. token=' + token, 'account=' + account)
          if (this._store) {
            await this._store.load(account)
            if (this._store.get(account) !== token) {
              throw new Error('incorrect token for account.' +
                ' account=' + account +
                ' token=' + token)
            }
            this._store.set(account, token)
          }

          if (this._connect) {
            await this._connect(this._prefix + account, authPacket, {
              ws: wsIncoming,
              req
            })
          }

          wsIncoming.send(BtpPacket.serializeResponse(authPacket.requestId, []))
        } catch (err) {
          if (authPacket) {
            debug('not accepted error during auth. error=', err)
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              data: err.message || err.name,
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

  async disconnect () {
    if (this._disconnect) {
      await this._disconnect()
    }

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

  async sendData (buffer) {
    const parsedPacket = IlpPacket.deserializeIlpPacket(buffer)

    let destination
    let isPrepare = false
    switch (parsedPacket.type) {
      case IlpPacket.Type.TYPE_ILP_PAYMENT:
      case IlpPacket.Type.TYPE_ILP_FORWARDED_PAYMENT:
        destination = parsedPacket.data.account
        break
      case IlpPacket.Type.TYPE_ILP_PREPARE:
        isPrepare = true
        destination = parsedPacket.data.destination
        if (this._sendPrepare) {
          this._sendPrepare(destination, parsedPacket)
        }
        break
      case IlpPacket.Type.TYPE_ILQP_LIQUIDITY_REQUEST:
      case IlpPacket.Type.TYPE_ILQP_BY_SOURCE_REQUEST:
      case IlpPacket.Type.TYPE_ILQP_BY_DESTINATION_REQUEST:
        destination = parsedPacket.data.destinationAccount
        break
      default:
        throw new Error('can\'t route packet with no destination. type=' + parsedPacket.type)
    }

    if (destination === 'peer.config') {
      return ILDCP.serializeIldcpResponse(this._hostIldcpInfo)
    }

    if (!destination.startsWith(this._prefix)) {
      throw new Error(`can't route packet that is not meant for one of my clients. destination=${destination} prefix=${this._prefix}`)
    }

    const response = await this._call(destination, {
      type: BtpPacket.TYPE_MESSAGE,
      requestId: crypto.randomBytes(4).readUInt32BE(),
      data: { protocolData: [{
        protocolName: 'ilp',
        contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
        data: buffer
      }] }
    })

    const ilpResponse = response.protocolData
      .filter(p => p.protocolName === 'ilp')[0]

    if (isPrepare && this._handlePrepareResponse) {
      this._handlePrepareResponse(destination,
        IlpPacket.deserializeIlpPacket(ilpResponse.data),
        parsedPacket)
    }

    return ilpResponse
      ? ilpResponse.data
      : Buffer.alloc(0)
  }

  async _handleData (from, btpPacket) {
    const { ilp } = this.protocolDataToIlpAndCustom(btpPacket.data)

    if (ilp) {
      const parsedPacket = IlpPacket.deserializeIlpPacket(ilp)

      if (parsedPacket.data.destination === 'peer.config') {
        debug('responding to ILDCP request. clientAddress=%s', from)
        return [{
          protocolName: 'ilp',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: await ILDCP.serve({
            requestPacket: ilp,
            handler: () => ({
              ...this._hostIldcpInfo,
              clientAddress: from
            }),
            serverAddress: this._hostIldcpInfo.clientAddress
          })
        }]
      }
    }

    if (this._handleCustomData) {
      debug('passing non-ILDCP data to custom handler')
      return this._handleCustomData(from, btpPacket)
    }

    if (!ilp) {
      debug('invalid packet, no ilp protocol data. from=%s', from)
      throw new Error('invalid packet, no ilp protocol data.')
    }

    if (!this._dataHandler) {
      throw new Error('no request handler registered')
    }

    const response = await this._dataHandler(ilp)
    return this.ilpAndCustomToProtocolData({ ilp: response })
  }

  async _handleOutgoingBtpPacket (to, btpPacket) {
    if (!to.startsWith(this._prefix)) {
      throw new Error(`invalid destination, must start with prefix. destination=${to} prefix=${this._prefix}`)
    }

    const account = this.ilpAddressToAccount(to)
    const connections = this._connections.get(account)

    if (!connections) {
      throw new Error('No clients connected for account ' + account)
    }

    Array.from(connections).map(wsIncoming => {
      const result = new Promise(resolve => wsIncoming.send(BtpPacket.serialize(btpPacket), resolve))

      result.catch(err => {
        const errorInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
        debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
      })
    })

    return null
  }
}

Plugin.version = 2

module.exports = Plugin
