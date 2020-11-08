/* eslint-env mocha */

const assert = require('assert')

const client = require('./client')
const server = require('./server')
const parameters = require('./parameters')
const SRPInteger = require('./lib/srp-integer')

describe('Secure Remote Password', () => {
  [1024, 2048].forEach(group => {
    it(`should authenticate a user using group ${group}`, () => {
      const params = parameters(group)
      const username = 'linus@folkdatorn.se'
      const password = '$uper$ecure'

      const salt = client.generateSalt(params)
      const privateKey = client.derivePrivateKey(salt, username, password, params)
      const verifier = client.deriveVerifier(privateKey, params)

      const clientEphemeral = client.generateEphemeral(params)
      const serverEphemeral = server.generateEphemeral(verifier, params)

      const clientSession = client.deriveSession(clientEphemeral.secret, serverEphemeral.public, salt, username, privateKey, params)
      const serverSession = server.deriveSession(serverEphemeral.secret, clientEphemeral.public, salt, username, verifier, clientSession.proof, params)

      client.verifySession(clientEphemeral.public, clientSession, serverSession.proof, params)

      assert.strictEqual(clientSession.key, serverSession.key, params)
    })
  })
})

describe('SRPInteger', () => {
  it('should keep padding when going back and forth', () => {
    assert.strictEqual(SRPInteger.fromHex('a').toHex(), 'a')
    assert.strictEqual(SRPInteger.fromHex('0a').toHex(), '0a')
    assert.strictEqual(SRPInteger.fromHex('00a').toHex(), '00a')
    assert.strictEqual(SRPInteger.fromHex('000a').toHex(), '000a')
    assert.strictEqual(SRPInteger.fromHex('0000a').toHex(), '0000a')
    assert.strictEqual(SRPInteger.fromHex('00000a').toHex(), '00000a')
    assert.strictEqual(SRPInteger.fromHex('000000a').toHex(), '000000a')
    assert.strictEqual(SRPInteger.fromHex('0000000a').toHex(), '0000000a')
    assert.strictEqual(SRPInteger.fromHex('00000000a').toHex(), '00000000a')
  })
})
