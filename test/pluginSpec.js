'use strict' /* eslint-env mocha */

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
const base64url = require('base64url')
const sendAuthPaket = require('./helper/btp-util')
const Token = require('../src/token')

function sha256 (token) {
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
      this.serverUrl = 'ws://localhost:' + this.port
    })

    describe('new account', function () {
      it('stores hashed token if account does not exist', async function () {
        const spy = sinon.spy(this.plugin._store, 'set')
        await sendAuthPaket(this.serverUrl, 'acc', 'secret_token')

        // assert that a new account was written to the store with a hashed token
        const expectedToken = sha256('secret_token')
        assert.isTrue(spy.calledWith('acc:hashed-token', expectedToken),
          `expected new account written to store with value ${expectedToken}, but wasn't`)
      })

      it('does not race when storing the token', async function () {
        const realStoreLoad = this.plugin._store.load.bind(this.plugin._store)
        sinon.stub(this.plugin._store, 'load').onFirstCall().callsFake(async (...args) => {
          // forces a race condition
          await sendAuthPaket(this.serverUrl, 'acc', '2nd_secret_token')
          return realStoreLoad(...args)
        })

        const msg = await sendAuthPaket(this.serverUrl, 'acc', '1st_secret_token')
        assert.strictEqual(msg.type, BtpPacket.TYPE_ERROR, 'expected an BTP error')
        assert.strictEqual(msg.data.code, 'F00')
        assert.strictEqual(msg.data.name, 'NotAcceptedError')
        assert.match(msg.data.data, /incorrect token for account/)

        assert.strictEqual(this.plugin._store.get('acc:hashed-token'), sha256('2nd_secret_token'))
      })
    })

    describe('existing account', function () {
      beforeEach(function () {
        new Token({
          account: 'acc',
          token: 'secret_token',
          store: this.plugin._store
        }).save()
      })

      it('fails if received token does not match stored token', async function () {
        const msg = await sendAuthPaket(this.serverUrl, 'acc', 'wrong_token')

        assert.strictEqual(msg.type, BtpPacket.TYPE_ERROR, 'expected an BTP error')
        assert.strictEqual(msg.data.code, 'F00')
        assert.strictEqual(msg.data.name, 'NotAcceptedError')
        assert.match(msg.data.data, /incorrect token for account/)
      })

      it('succeeds if received token matches stored token', async function () {
        const msg = await sendAuthPaket(this.serverUrl, 'acc', 'secret_token')
        assert.strictEqual(msg.type, BtpPacket.TYPE_RESPONSE)
      })

      it('migrates an unhashed token', async function () {
        this.plugin._store.set('other_acc:token', 'unhashed')
        const token = await Token.load({account: 'other_acc', store: this.plugin._store})
        assert.isUndefined(this.plugin._store.get('other_acc:token'))
        assert.strictEqual(token._account, 'other_acc')
        assert.strictEqual(token._hashedToken, sha256('unhashed'))
      })
    })
  })

  describe('sendData', function () {
    beforeEach(function () {
      this.fulfillment = crypto.randomBytes(32)
      this.condition = crypto.createHash('sha256')
        .update(this.fulfillment)
        .digest()
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

    it('should return ilp reject when incorrect fulfill is returned', async function () {
      this.fulfillment = Buffer.alloc(32)

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
        code: 'F05',
        triggeredBy: 'test.example',
        message: `condition and fulfillment don't match. condition=${this.condition.toString('hex')} fulfillment=0000000000000000000000000000000000000000000000000000000000000000`,
        data: Buffer.alloc(0)
      })
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
