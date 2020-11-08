'use strict'

const SRPInteger = require('./lib/srp-integer')

exports.generateSalt = function ({ hashOutputBytes }) {
  // s    User's salt
  const s = SRPInteger.randomInteger(hashOutputBytes)

  return s.toHex()
}

// H()  One-way hash function
exports.derivePrivateKey = function (salt, username, password, { H }) {
  // s    User's salt
  // I    Username
  // p    Cleartext Password
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const p = String(password)

  // x = H(s, H(I | ':' | p))  (s is chosen randomly)
  const x = H(s, H(`${I}:${p}`))

  return x.toHex()
}

// N    A large safe prime (N = 2q+1, where q is prime)
// g    A generator modulo N
exports.deriveVerifier = function (privateKey, { N, g }) {
  // x    Private key (derived from p and s)
  const x = SRPInteger.fromHex(privateKey)

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N)

  return v.toHex()
}

// N    A large safe prime (N = 2q+1, where q is prime)
// g    A generator modulo N
exports.generateEphemeral = function ({ N, g, hashOutputBytes }) {
  // A = g^a                  (a = random number)
  const a = SRPInteger.randomInteger(hashOutputBytes)
  const A = g.modPow(a, N)

  return {
    secret: a.toHex(),
    public: A.toHex()
  }
}

// N    A large safe prime (N = 2q+1, where q is prime)
// g    A generator modulo N
// k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// H()  One-way hash function
exports.deriveSession = function (clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey, { N, g, k, H }) {
  // a    Secret ephemeral values
  // B    Public ephemeral values
  // s    User's salt
  // I    Username
  // x    Private key (derived from p and s)
  const a = SRPInteger.fromHex(clientSecretEphemeral)
  const B = SRPInteger.fromHex(serverPublicEphemeral)
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const x = SRPInteger.fromHex(privateKey)

  // A = g^a                  (a = random number)
  const A = g.modPow(a, N)

  // B % N > 0
  if (B.mod(N).equals(SRPInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('The server sent an invalid public ephemeral')
  }

  // u = H(A, B)
  const u = H(A, B)

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)

  // K = H(S)
  const K = H(S)

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = H(H(N).xor(H(g)), H(I), s, A, B, K)

  return {
    key: K.toHex(),
    proof: M.toHex()
  }
}

// H()  One-way hash function
exports.verifySession = function (clientPublicEphemeral, clientSession, serverSessionProof, { H }) {
  // A    Public ephemeral values
  // M    Proof of K
  // K    Shared, strong session key
  const A = SRPInteger.fromHex(clientPublicEphemeral)
  const M = SRPInteger.fromHex(clientSession.proof)
  const K = SRPInteger.fromHex(clientSession.key)

  // H(A, M, K)
  const expected = H(A, M, K)
  const actual = SRPInteger.fromHex(serverSessionProof)

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('Server provided session proof is invalid')
  }
}
