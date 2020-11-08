/// <reference path="./parameters.d.ts" />

export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export function generateSalt(params: Parameters): string
export function derivePrivateKey(salt: string, username: string, password: string, params: Parameters): string
export function deriveVerifier(privateKey: string, params: Parameters): string
export function generateEphemeral(params: Parameters): Ephemeral
export function deriveSession(clientSecretEphemeral: string, serverPublicEphemeral: string, salt: string, username: string, privateKey: string, params: Parameters): Session
export function verifySession(clientPublicEphemeral: string, clientSession: Session, serverSessionProof: string, params: Parameters): void
