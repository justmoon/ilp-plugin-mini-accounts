'use strict'

const assert = require('assert')
const base64url = require('base64url')
const crypto = require('crypto')

const TOKEN = account => account + ':hashed-token'
const DEPRECATED_TOKEN = account => account + ':token'

function sha256 (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

class Token {
  constructor ({account, token, store}) {
    this._account = account
    this._hashedToken = token && sha256(token)
    this._store = store
  }

  equal (otherToken) {
    assert(otherToken, 'parameter otherToken is required')
    return this._account === otherToken._account &&
            this._hashedToken === otherToken._hashedToken
  }

  exists () {
    return !!(this._store && this._store.get(TOKEN(this._account)))
  }

  save () {
    this._store.set(TOKEN(this._account), this._hashedToken)
  }

  delete () {
    this._store.delete(TOKEN(this._account))
  }

  static async load ({account, store}) {
    const ctor = (account, hashedToken, store) => {
      const t = new Token({account, store})
      t._hashedToken = hashedToken
      return t
    }

    await store.load(TOKEN(account))
    const hashedToken = store.get(TOKEN(account))
    if (hashedToken) {
      return ctor(account, hashedToken, store)
    }

    await store.load(DEPRECATED_TOKEN(account))
    const token = store.get(DEPRECATED_TOKEN(account))
    if (token) {
      store.set(TOKEN(account), sha256(token))
      store.delete(DEPRECATED_TOKEN(account))
      return ctor(account, sha256(token), store)
    }

    return ctor() // return empty object
  }
}

module.exports = Token
