import { fromByteArray, toByteArray } from 'base64-js';
import {
  Handshake,
  Session,
  startHandshake as startHandshakeType,
} from './types';

export const startHandshake: typeof startHandshakeType = async function startHandshake() {
  const keypair = await generateKeypair();

  const handshake: Handshake = {
    publicKey: fromByteArray(
      new Uint8Array(await crypto.subtle.exportKey('spki', keypair.publicKey))
    ),
    async finish(peerPublicKey: string) {
      const sharedKey = await derive(keypair.privateKey, peerPublicKey);

      const session: Session = {
        async encrypt(plaintext: string | BufferSource) {
          return await encrypt(sharedKey, plaintext);
        },
        async decrypt(ciphertext: Uint8Array, encoding?: 'utf8'): Promise<any> {
          const plaintext = await decrypt(sharedKey, ciphertext);
          if (encoding === 'utf8') {
            return new TextDecoder().decode(plaintext);
          } else {
            return plaintext;
          }
        },
      };

      return session;
    },
  };

  return handshake;
};

async function generateKeypair() {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-521',
    },
    false,
    ['deriveKey']
  );
}

async function derive(myKey: CryptoKey, peerPublicKey: string) {
  const publicKey = toByteArray(peerPublicKey);
  const key = await crypto.subtle.importKey(
    'spki',
    publicKey,
    {
      name: 'ECDH',
      namedCurve: 'P-521',
    },
    false,
    []
  );

  const sharedKey = await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: key,
    },
    myKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );

  return sharedKey;
}

async function encrypt(
  key: CryptoKey,
  plaintext: string | BufferSource
): Promise<Uint8Array> {
  if (typeof plaintext === 'string') {
    plaintext = new TextEncoder().encode(plaintext);
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      key,
      plaintext as any
    )
  );

  const cryptogram = new Uint8Array(iv.length + ciphertext.length);
  cryptogram.set(iv);
  cryptogram.set(ciphertext, iv.length);

  return cryptogram;
}

async function decrypt(key: CryptoKey, ciphertext: Uint8Array) {
  const iv = ciphertext.slice(0, 12);
  const c = ciphertext.slice(12);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128,
    },
    key,
    c
  );

  return new Uint8Array(plaintext);
}
