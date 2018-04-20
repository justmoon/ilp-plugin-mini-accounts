'use strict'

const BtpPacket = require('btp-packet')
const WebSocket = require('ws')

module.exports = async function sendAuthPaket (serverUrl, account, token) {
  const protocolData = [{
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

  const ws = new WebSocket(serverUrl)
  await new Promise(resolve => {
    ws.on('open', () => resolve())
  })

  const result = new Promise(resolve => ws.on('message', (msg) => {
    resolve(BtpPacket.deserialize(msg))
  }))

  await new Promise((resolve) => ws.send(BtpPacket.serialize({
    type: BtpPacket.TYPE_MESSAGE,
    requestId: 1,
    data: { protocolData }
  }), resolve))

  return result
}
