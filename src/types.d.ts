export async function encrypt(plaintext: string): Promise<Uint8Array>;
export async function encrypt(plaintext: BufferSource): Promise<Uint8Array>;

export async function decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
export async function decrypt(
  ciphertext: Uint8Array,
  encoding: 'utf8'
): Promise<string>;

export type Session = {
  encrypt: typeof encrypt;
  decrypt: typeof decrypt;
};

export async function finish(peerPublicKey: string): Promise<Session>;

export type Handshake = {
  publicKey: string;
  finish: typeof finish;
};

export async function startHandshake(): Promise<Handshake>;
