const express = require('express');
const { createPrivateKey, createPublicKey, generateKeyPairSync, privateDecrypt, publicEncrypt, sign, verify } = require('crypto');

const app = express();
app.use(express.json());

// create sender key pair
const { privateKey: senderPrivateKey, publicKey: senderPublicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
// create receiver key pair
const { publicKey: receiverPublicKey, privateKey: receiverPrivateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Route to send a message
app.post('/send-message', (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  // encrypt the message using the receiver's public key
  const encryptedMessage = publicEncrypt(receiverPublicKey, Buffer.from(message));

  // sign the message using the sender's private key
  const signature = sign('sha256', Buffer.from(message), senderPrivateKey);

  res.json({
    encryptedMessage: encryptedMessage.toString('base64'),
    signature: signature.toString('base64'),
    senderPublicKey: senderPublicKey.export({ type: 'pkcs1', format: 'pem' }),
  });
});

// Route to receive a message
app.post('/receive-message', (req, res) => {
  const { encryptedMessage, signature, senderPublicKey: senderPublicKeyPem } = req.body;

  if (!encryptedMessage || !signature || !senderPublicKeyPem) {
    return res.status(400).json({ error: 'Encrypted message, signature, and sender public key are required' });
  }

  const senderPublicKey = createPublicKey(senderPublicKeyPem);

  // decrypt the message using the receiver's private key
  let decryptedMessage;
  try {
    decryptedMessage = privateDecrypt(receiverPrivateKey, Buffer.from(encryptedMessage, 'base64')).toString('utf8');
  } catch (error) {
    return res.status(400).json({ error: 'Failed to decrypt message' });
  }

  // verify the signature using the sender's public key
  const isVerified = verify('sha256', Buffer.from(decryptedMessage), senderPublicKey, Buffer.from(signature, 'base64'));

  res.json({
    decryptedMessage,
    isVerified,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
