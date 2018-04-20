'use strict' /* eslint-env mocha */

const chai = require('chai')
chai.use(require('chai-as-promised'))
const assert = chai.assert

const OriginWhitelist = require('../src/lib/origin-whitelist')

describe('Whitelist Spec', function () {
  describe('constructor', function () {
    it('instantiates an object with an empty whitelist', () => {
      const o = new OriginWhitelist()
      assert.isObject(o)
      assert.isArray(o._whitelist)
      assert.isEmpty(o._whitelist)
    })

    it('takes an array of allowed origins', () => {
      const allowedOrigins = [/chrome-extension:\/\/someextensionid/, 'http://example.com']
      const w = new OriginWhitelist(allowedOrigins)
      const exptectedWhitelist = allowedOrigins.map(i => new RegExp(i))
      assert.deepEqual(w._whitelist, exptectedWhitelist)
    })

    it('validates paramter type', () => {
      assert.throws(() => new OriginWhitelist('string literal'), 'parameter allowedOrigins must be an array')
    })
  })

  describe('addOrigin', () => {
    beforeEach(() => {
      this.whitelist = new OriginWhitelist()
    })

    it('adds an origin', () => {
      const expectedOrigin = 'http://example.com'
      this.whitelist.add(expectedOrigin)
      assert.deepEqual(this.whitelist._whitelist, [ new RegExp(expectedOrigin) ])
    })
  })

  describe('isOk', () => {
    beforeEach(() => {
      this.whitelist = new OriginWhitelist()
      this.whitelist.add('http://example.com')
    })

    it('returns true if an origin is whitelisted', () => {
      assert.isTrue(this.whitelist.isOk('http://example.com'))
    })

    it('returns false if an origin is not whitelisted', () => {
      assert.isFalse(this.whitelist.isOk('http://no-example.com'))
    })

    it('matches a regular expression', () => {
      this.whitelist.add('chrome-extension://.*')
      assert.isTrue(this.whitelist.isOk('chrome-extension://someextensionid'))
    })
  })
})
