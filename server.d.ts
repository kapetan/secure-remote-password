/// <reference path="./parameters.d.ts" />

export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export function generateEphemeral(verifier: string, params: Parameters): Ephemeral
export function deriveSession(serverSecretEphemeral: string, clientPublicEphemeral: string, salt: string, username: string, verifier: string, clientSessionProof: string, params: Parameters): Session
