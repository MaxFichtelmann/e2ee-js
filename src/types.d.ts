/**
 * A session that is established after performing a key exchange
 */
export type Session = {
  /**
   * encrypt a utf-8 encoded string with the session key and AES/GCM
   *
   * @param plaintext the utf-8 encoded string to encrypt
   * @returns A Promise that resolves into `iv || ciphertext`
   */
  encrypt(plaintext: string): Promise<Uint8Array>;
  /**
   * encrypt a binary with the session key and AES/GCM
   *
   * @param plaintext the binary to encrypt
   * @returns A Promise that resolves into `iv || ciphertext`
   */
  encrypt(plaintext: BufferSource): Promise<Uint8Array>;

  /**
   * decrypts a ciphertext into a plaintext binary with the session key and AES/GCM
   *
   * @param ciphertext the encrypted binary
   * @returns A Promise that resolves into the plaintext binary
   */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
  /**
   * decrypts a ciphertext into a plaintext string with the session key and AES/GCM
   *
   * @param ciphertext the encrypted binary
   * @param encoding the text encoding (`utf8`)
   * @returns A Promise that resolves into the plaintext string
   */
  decrypt(ciphertext: Uint8Array, encoding: 'utf8'): Promise<string>;
};

/**
 * A handshake representing an in-progress diffie-hellman key exchange
 */
export type Handshake = {
  /** the base64 encoded subject-public-keyinfo structure of the ephemeral public key */
  publicKey: string;
  /**
   * Start a session by deriving a shared secret from the base64 encoded public key of the peer.
   *
   * @param peerPublicKey the base64 encoded public key of the peer
   * @returns the session with encrypt/decrypt capabilities
   */
  finish(peerPublicKey: string): Promise<Session>;
};

/**
 * start a handshake to establish an end-to-end encrypted session using ECDHE and AES/GCM, powered by web-crypto.
 * While the use of crypto.subtle reduces external dependencies to a minimum, it is only available in a secure context.
 * 
 * @returns an in-progress e2ee handshake
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 * 
 * @example
 * ```js
    const handshakeA = await startHandshake();
    const publicKeyA = handshakeA.publicKey;
    
        const handshakeB = await startHandshake();
        const sessionB = await handshakeB.finish(publicKeyA);
        const publicKeyB = handshakeB.publicKey;

    const sessionA = await handshakeA.finish(publicKeyB);
    const encrypted = await sessionA.encrypt('Hello World!');

        const decrypted = await sessionB.decrypt(encrypted, 'utf8');
        // 'Hello World!'

 * ```
 */
export async function startHandshake(): Promise<Handshake>;
