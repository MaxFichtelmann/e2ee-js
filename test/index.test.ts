import { startHandshake } from '../src';
import crypto from 'crypto';

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: (crypto.webcrypto as any).subtle,
    getRandomValues(typedArray: Uint8Array) {
      const { BYTES_PER_ELEMENT, length } = typedArray;
      const totalBytes = BYTES_PER_ELEMENT * length;
      const { buffer } = crypto.randomBytes(totalBytes);
      return Reflect.construct(typedArray.constructor, [buffer]);
    },
  },
});

global.self.TextDecoder = require('util').TextDecoder;
global.self.TextEncoder = require('util').TextEncoder;

describe('a full handshake', () => {
  it('works', async () => {
    const handshakeA = await startHandshake();
    const handshakeB = await startHandshake();
    expect(handshakeA).toBeDefined();

    const sessionB = await handshakeB.finish(handshakeA.publicKey);
    const sessionA = await handshakeA.finish(handshakeB.publicKey);
    expect(sessionA).toBeDefined();

    const encrypted = await sessionA.encrypt('Hello World!');
    const decrypted = await sessionB.decrypt(encrypted, 'utf8');

    expect(decrypted).toBe('Hello World!');
  });
});
