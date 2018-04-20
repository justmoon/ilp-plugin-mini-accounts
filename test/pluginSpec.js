'use strict'

const BtpPacket = require('btp-packet')
const crypto = require('crypto')
const IlpPacket = require('ilp-packet')
const getPort = require('get-port')
const chai = require('chai')
chai.use(require('chai-as-promised'))
const assert = chai.assert
const sinon = require('sinon')

const PluginMiniAccounts = require('..')
const Store = require('ilp-store-memory')
const WebSocket = require('ws')
const base64url = require('base64url')

function tokenToAccount (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

describe('Mini Accounts Plugin', () => {
  beforeEach(async function () {
    this.port = await getPort()
    this.plugin = new PluginMiniAccounts({
      port: this.port,
      debugHostIldcpInfo: {
        clientAddress: 'test.example'
      },
      _store: new Store()
    })
    await this.plugin.connect()

    this.from = 'test.example.35YywQ-3GYiO3MM4tvfaSGhty9NZELIBO3kmilL0Wak'

    this.fulfillment = crypto.randomBytes(32)
    this.condition = crypto.createHash('sha256')
      .update(this.fulfillment)
      .digest()
  })

  afterEach(async function () {
    await this.plugin.disconnect()
  })

  describe('Authentication', function () {
    beforeEach(async function () {
      this.ws = new WebSocket('ws://localhost:' + this.port)
      await new Promise((resolve) => {
        this.ws.on('open', () => resolve())
      })

      this.createAuthData = (account, token) => {
        return [{
          protocolName: 'auth',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: Buffer.from([])
        }, {
          protocolName: 'auth_username',
          contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
          data: Buffer.from(account, 'utf8')
        }, {
          protocolName: 'auth_token',
          contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
          data: Buffer.from(token, 'utf8')
        }]
      }
    })

    it('stores hashed token if account does not exist', async function () {
      const spy = sinon.spy(this.plugin._store, 'set')

      // send auth packet and wait for response
      await new Promise((resolve) => this.ws.send(BtpPacket.serialize({
        type: BtpPacket.TYPE_MESSAGE,
        requestId: 1,
        data: { protocolData: this.createAuthData('acc', 'secret_token') }
      }), resolve))
      await new Promise(resolve => this.ws.on('message', resolve))

      // assert that a new account was written to the store with a hashed token
      const hashedToken = tokenToAccount('secret_token')
      assert.isTrue(spy.calledWith('acc:token', hashedToken),
        `expected new account written to store with value ${hashedToken}, but wasn't`)
    })

    describe('if account exists', function () {
      beforeEach(function () {
        this.plugin._store.set('acc:token', tokenToAccount('secret_token'))
      })

      it('fails if received token does not match stored token', async function () {
        // send auth packet and wait for response
        await new Promise((resolve) => this.ws.send(BtpPacket.serialize({
          type: BtpPacket.TYPE_MESSAGE,
          requestId: 1,
          data: { protocolData: this.createAuthData('acc', 'wrong_token') }
        }), resolve))
        const msg = await new Promise(resolve => this.ws.on('message', (msg) => {
          resolve(BtpPacket.deserialize(msg))
        }))
        assert.strictEqual(msg.type, BtpPacket.TYPE_ERROR)
        assert.strictEqual(msg.data.code, 'F00')
        assert.strictEqual(msg.data.name, 'NotAcceptedError')
        assert.match(msg.data.data, /incorrect token for account/)
      })

      it('succeeds if received token matches stored token', async function () {
        // send auth packet and wait for response
        await new Promise((resolve) => this.ws.send(BtpPacket.serialize({
          type: BtpPacket.TYPE_MESSAGE,
          requestId: 1,
          data: { protocolData: this.createAuthData('acc', 'secret_token') }
        }), resolve))
        const msg = await new Promise(resolve => this.ws.on('message', (msg) => {
          resolve(BtpPacket.deserialize(msg))
        }))
        assert.strictEqual(msg.type, BtpPacket.TYPE_RESPONSE)
      })
    })
  })

  describe('sendData', function () {
    beforeEach(function () {
      this.plugin._call = async (dest, packet) => {
        return { protocolData: [ {
          protocolName: 'ilp',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: IlpPacket.serializeIlpFulfill({
            fulfillment: this.fulfillment,
            data: Buffer.alloc(0)
          })
        } ] }
      }
    })

    it('should return ilp reject when _handlePrepareResponse throws', async function () {
      this.plugin._handlePrepareResponse = () => {
        throw new IlpPacket.Errors.UnreachableError('cannot be reached')
      }

      const result = await this.plugin.sendData(IlpPacket.serializeIlpPrepare({
        destination: this.from,
        amount: '123',
        executionCondition: this.condition,
        expiresAt: new Date(Date.now() + 10000),
        data: Buffer.alloc(0)
      }))

      const parsed = IlpPacket.deserializeIlpPacket(result)

      assert.equal(parsed.typeString, 'ilp_reject')
      assert.deepEqual(parsed.data, {
        code: 'F02',
        triggeredBy: 'test.example',
        message: 'cannot be reached',
        data: Buffer.alloc(0)
      })
    })
  })
})
