# Secure Remote Password for JavaScript

A modern [SRP](http://srp.stanford.edu) implementation for Node.js and Web Browsers. Forked from [LinusU/secure-remote-password](https://github.com/LinusU/secure-remote-password).

## Installation

```sh
npm install --save @kapetan/secure-remote-password
```

## Usage

### Signing up

When creating an account with the server, the client will provide a salt and a verifier for the server to store. They are calculated by the client as follows:

```js
const srp = require('secure-remote-password/client')
const params = require('secure-remote-password/parameters')()

// These should come from the user signing up
const username = 'linus@folkdatorn.se'
const password = '$uper$ecure'

const salt = srp.generateSalt(params)
const privateKey = srp.derivePrivateKey(salt, username, password, params)
const verifier = srp.deriveVerifier(privateKey, params)

console.log(salt)
//=> FB95867E...

console.log(verifier)
//=> 9392093F...

// Send `username`, `salt` and `verifier` to the server
```

*note:* `derivePrivateKey` is provided for completeness with the SRP 6a specification. It is however recommended to use some form of "slow hashing", like [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), to reduce the viability of a brute force attack against the verifier.

### Logging in

Authenticating with the server involves mutliple steps.

**1** - The client generates a secret/public ephemeral value pair.

```js
const srp = require('secure-remote-password/client')
const params = require('secure-remote-password/parameters')()

// This should come from the user logging in
const username = 'linus@folkdatorn.se'

const clientEphemeral = srp.generateEphemeral(params)

console.log(clientEphemeral.public)
//=> DE63C51E...

// Send `username` and `clientEphemeral.public` to the server
```

**2** - The server receives the client's public ephemeral value and username. Using the username we retrieve the `salt` and `verifier` from our user database. We then generate our own ephemeral value pair.

*note:* if no user cannot be found in the database, a bogus salt and ephemeral value should be returned, to avoid leaking which users have signed up

```js
const srp = require('secure-remote-password/server')
const params = require('secure-remote-password/parameters')()

// This should come from the user database
const salt = 'FB95867E...'
const verifier = '9392093F...'

const serverEphemeral = srp.generateEphemeral(verifier, params)

console.log(serverEphemeral.public)
//=> DA084F5C...

// Store `serverEphemeral.secret` for later use
// Send `salt` and `serverEphemeral.public` to the client
```

**3** - The client can now derive the shared strong session key, and a proof of it to provide to the server.

```js
const srp = require('secure-remote-password/client')
const params = require('secure-remote-password/parameters')()

// This should come from the user logging in
const password = '$uper$ecret'

const privateKey = srp.derivePrivateKey(salt, username, password, params)
const clientSession = srp.deriveSession(clientEphemeral.secret, serverPublicEphemeral, salt, username, privateKey, params)

console.log(clientSession.key)
//=> 2A6FF04E...

console.log(clientSession.proof)
//=> 6F8F4AC3

// Send `clientSession.proof` to the server
```

**4** - The server is also ready to derive the shared strong session key, and can verify that the client has the same key using the provided proof.

```js
const srp = require('secure-remote-password/server')
const params = require('secure-remote-password/parameters')()

// Previously stored `serverEphemeral.secret`
const serverSecretEphemeral = '784D6E83...'

const serverSession = srp.deriveSession(serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof, params)

console.log(serverSession.key)
//=> 2A6FF04E...

console.log(serverSession.proof)
//=> 92561B95

// Send `serverSession.proof` to the client
```

**5** - Finally, the client can verify that the server have derived the correct strong session key, using the proof that the server sent back.

```js
const srp = require('secure-remote-password/client')
const params = require('secure-remote-password/parameters')()

srp.verifySession(clientEphemeral.public, clientSession, serverSessionProof, params)

// All done!
```

## API

### `Client`

```js
const Client = require('secure-remote-password/client')
```

#### `Client.generateSalt(params) => string`

Generate a salt suitable for computing the verifier with.

#### `Client.derivePrivateKey(salt, username, password, params) => string`

Derives a private key suitable for computing the verifier with.

#### `Client.deriveVerifier(privateKey, params) => string`

Derive a verifier to be stored for subsequent authentication atempts.

#### `Client.generateEphemeral(params) => { secret: string, public: string }`

Generate ephemeral values used to initiate an authentication session.

#### `Client.deriveSession(clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey, params) => { key: string, proof: string }`

Comptue a session key and proof. The proof is to be sent to the server for verification.

#### `Client.verifySession(clientPublicEphemeral, clientSession, serverSessionProof, params) => void`

Verifies the server provided session proof. Throws an error if the session proof is invalid.

### `Server`

```js
const Server = require('secure-remote-password/server')
```

#### `generateEphemeral(verifier, params)`

Generate ephemeral values used to continue an authentication session.

#### `deriveSession(serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof, params)`

Comptue a session key and proof. The proof is to be sent to the client for verification.

Throws an error if the session proof from the client is invalid.

### `Parameters`

```js
const parameters = require('secure-remote-password/parameters')
```

#### `parameters(group)`

Get SRP constants with provided prime length. Group can be either `1024` or `2048` (default).
