const net = require('net');
const crypto = require('crypto');

async function sha256(plaintext) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}


async function generateAESKey() {
    return crypto.randomBytes(32);
}

function encryptWithRSA(publicKey, data) {
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        data
    );
}


function importRSAPublicKey(pem) {
    return crypto.createPublicKey({
        key: pem,
        format: 'pem',
        type: 'spki',
    });
}

async function connectToServer(handle, authKey = null, options = {port: 8080}) {
    const client = net.createConnection(options, async () => {
        console.log('Connected to server');

        client.once('data', async (data) => {
            const serverRSAPublicKeyPEM = data.toString();
            console.log('Received RSA public key from server');

            const serverRSAPublicKey = importRSAPublicKey(serverRSAPublicKeyPEM);

            if (authKey != null) {
                const encryptedAuthKey = encryptWithRSA(serverRSAPublicKey, authKey)
                const encryptedHashedAuthKey = encryptWithRSA(serverRSAPublicKey, sha256(authKey))
                client.write(encryptedAuthKey)
                client.write(encryptedHashedAuthKey)
                console.log('Encrypted AUTH Key sent to server')
            }

            const aesKey = await generateAESKey();

            const encryptedAESKey = encryptWithRSA(serverRSAPublicKey, aesKey);
            client.write(encryptedAESKey);
            console.log('Encrypted AES key sent to server');

            await handle(client, aesKey);
        });
    });

    client.on('error', (err) => {
        console.error('Client error:', err);
    });

    client.on('end', () => {
        console.log('Disconnected from server');
    });
}

async function send(client, aesKey, text) {
    const nonce = crypto.randomBytes(12);

    const plaintext = text;
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);

    let encryptedMessage = cipher.update(plaintext, 'utf8');
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
    const authTag = cipher.getAuthTag();

    client.write(nonce);
    client.write(encryptedMessage);
    client.write(authTag);
    console.log('Encrypted message sent to server');
}

async function receive(client, aesKey) {
    client.on('data', (data) => {
        console.log('Received encrypted response from server');
        const nonceSize = 12;
        const authTagSize = 16;

        const receivedNonce = data.slice(0, nonceSize);
        const ciphertext = data.slice(nonceSize, -authTagSize);
        const receivedAuthTag = data.slice(-authTagSize);

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, receivedNonce);
        decipher.setAuthTag(receivedAuthTag);

        let decryptedMessage = decipher.update(ciphertext, null, 'utf8');
        decryptedMessage += decipher.final('utf8');
        return decryptedMessage
    });
}

async function sendAndReceive(client, aesKey, text) {
    send(client, aesKey, text)
    return receive(client, aesKey)
}