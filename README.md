# E2EE

E2EE - short for end-to-end encryption - is a method that prevents an observer from accessing data while it is being transferred between two parties.

This library implements key-exchange using ECDHE (ephemeral diffie-hellman) and encryption using AES-GCM.

## Install

    npm install @fichtelmax/e2ee

## Usage

Usage is usually distributed across 2 parties. In this example, Alice wants to exchange messages with bob:

```js
import { startHandshake } from '@fichtelmax/e2ee';

// alice starts with creating a handshake, which generates an ephemeral diffie-hellman keypair
const handshakeA = await startHandshake();
const publicKeyA = handshakeA.publicKey;

// alice then hands the public key of the generated keypair to bob

// bob starts a handshake himself and completes it with the public key of alice
const handshakeB = await startHandshake();
const sessionB = await handshakeB.finish(publicKeyA);
const publicKeyB = handshakeB.publicKey;

// bob hands his public key to alice

// alice finishes the handshake on her side. Both have now derived an identical AES session key.
const sessionA = await handshakeA.finish(publicKeyB);

// alice can now encrypt a message, send the encrypted message to bob.
const encrypted = await sessionA.encrypt('Hello World!');

// bob decrypts the message received by alice and gets the same plain text
const decrypted = await sessionB.decrypt(encrypted, 'utf8');
// 'Hello World!'
```

## Caveats

For threat models that include a man-in-the-middle that can modify messages during the handshake, the transmission of the public key needs to be secured on at least one side, for example by attaching a matching asymmetric digital signature.
