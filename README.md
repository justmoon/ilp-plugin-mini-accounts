# ILP Plugin Mini-Accounts

[![Greenkeeper badge](https://badges.greenkeeper.io/interledgerjs/ilp-plugin-mini-accounts.svg)](https://greenkeeper.io/)

- [Description](#description)
- [Example](#example)

## Description

ILP Plugin Mini-Accounts provides a way for many users to sign up for a
connector without the connector modifying its configuration. It is a type of
multi-user plugin, which means that it internally implements an extremely
barebones connector.

This plugin can be connected to with
[`ilp-plugin-btp`](https://github.com/interledgerjs/ilp-plugin-btp). Any secret
can be used to authenticate; it is then hashed and becomes your account
identifier. This has the advantage of requiring no UI-based signup flow nor any
database storing usernames and passwords. It has the disadvantage that password
recovery cannot be done, and only randomly generated passwords should be used.
Treat your credentials like you would treat a wallet secret for a
cryptocurrency.

Mini-Accounts currently has no internal balance logic. It is a planned feature
to support it in a similar way to [the connector's balance
logic.](https://github.com/interledgerjs/ilp-connector/issues/400#issuecomment-355223994).

## Example

```js
const plugin = new IlpPluginMiniAccounts({
  // A WebSocket server will run with these options, as described in:
  // https://github.com/websockets/ws/blob/master/doc/ws.md#new-websocketserveroptions-callback
  //
  // Any connections are expected to be ILP v4 over BTP, as discussed in:
  // https://github.com/interledger/rfcs/pull/360.
  //
  // The first packet should be an auth packet, but any random auth token will be accepted.

  wsOpts: {
    port: 6666
  }
})
```

Note that this module requires node version 8.3.0 or higher.
