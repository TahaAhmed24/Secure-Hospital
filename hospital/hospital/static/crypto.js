// All encryption happens client-side using Web Crypto API
class E2EECrypto {

    // ----------------------------
    // Generate RSA key pair for encryption
    // ----------------------------
    static async generateEncryptionKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        return keyPair;
    }

    // ----------------------------
    // Generate RSA key pair for signing
    // ----------------------------
    static async generateSigningKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["sign", "verify"]
        );
        return keyPair;
    }

    // ----------------------------
    // Export public key to PEM
    // ----------------------------
    static async exportPublicKey(publicKey) {
        const exported = await window.crypto.subtle.exportKey("spki", publicKey);
        const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
        return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
    }

    // Export private key to ArrayBuffer
    static async exportPrivateKey(privateKey) {
        const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
        return new Uint8Array(exported);
    }

    // ----------------------------
    // Import public key from PEM
    // ----------------------------
    static async importPublicKey(pemKey) {
        const pemContents = pemKey.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
    }

    static async importPrivateKey(keyData) {
        return await window.crypto.subtle.importKey(
            "pkcs8",
            keyData,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );
    }

    // ----------------------------
    // Import signing keys
    // ----------------------------
    static async importSigningPublicKey(pemKey) {
        const pemContents = pemKey.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            true,
            ["verify"]
        );
    }

    static async importSigningPrivateKey(keyData) {
        return await window.crypto.subtle.importKey(
            "pkcs8",
            keyData,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            true,
            ["sign"]
        );
    }

    // ----------------------------
    // Sign and verify
    // ----------------------------
    static async signData(data, privateKey) {
        return await window.crypto.subtle.sign(
            { name: "RSASSA-PKCS1-v1_5" },
            privateKey,
            data
        );
    }

    static async verifySignature(data, signature, publicKey) {
        return await window.crypto.subtle.verify(
            { name: "RSASSA-PKCS1-v1_5" },
            publicKey,
            signature,
            data
        );
    }

    // ----------------------------
    // Derive AES key from password
    // ----------------------------
    static async deriveKeyFromPassword(password, salt) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);

        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            passwordBuffer,
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 600000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // ----------------------------
    // Encrypt/decrypt private key with password
    // ----------------------------
    static async encryptPrivateKey(privateKey, password) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const derivedKey = await this.deriveKeyFromPassword(password, salt);
        const privateKeyData = await this.exportPrivateKey(privateKey);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            derivedKey,
            privateKeyData
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);

        return {
            salt: btoa(String.fromCharCode(...salt)),
            encryptedKey: btoa(String.fromCharCode(...combined))
        };
    }

    static async encryptPrivateKeyWithKey(privateKey, key) {
        const privateKeyData = await this.exportPrivateKey(privateKey);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            privateKeyData
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);

        return btoa(String.fromCharCode(...combined));
    }

    static async decryptPrivateKey(encryptedData, salt, password, isSigningKey = false) {
        const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
        const derivedKey = await this.deriveKeyFromPassword(password, saltBytes);

        const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            derivedKey,
            encrypted
        );

        return isSigningKey
            ? await this.importSigningPrivateKey(decrypted)
            : await this.importPrivateKey(decrypted);
    }

    // ----------------------------
    // Symmetric key for file encryption
    // ----------------------------
    static async generateSymmetricKey(extractable = true) {
        // File encryption keys are extractable by default (needed for sharing with other users)
        // Device keys should use generateDeviceKey() instead
        return await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            extractable,
            ["encrypt", "decrypt"]
        );
    }

    // Generate non-extractable device key (for local device encryption only)
    static async generateDeviceKey() {
        return await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            false,  // Non-extractable - cannot be exported
            ["encrypt", "decrypt"]
        );
    }

    static async encryptFile(fileData, symmetricKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            symmetricKey,
            fileData
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return combined;
    }

    static async decryptFile(encryptedData, symmetricKey) {
        const iv = encryptedData.slice(0, 12);
        const encrypted = encryptedData.slice(12);
        return await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            symmetricKey,
            encrypted
        );
    }

    // ----------------------------
    // Symmetric key encryption (for sharing)
    // ----------------------------
    static async encryptSymmetricKey(symmetricKey, publicKey) {
        const exported = await window.crypto.subtle.exportKey("raw", symmetricKey);
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            exported
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    static async decryptSymmetricKey(encryptedKey, privateKey) {
        const encryptedBytes = Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBytes
        );

        return await window.crypto.subtle.importKey(
            "raw",
            decrypted,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // ----------------------------
    // Text encryption (filenames, metadata)
    // ----------------------------
    static async encryptText(text, symmetricKey) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const encrypted = await this.encryptFile(data, symmetricKey);
        return btoa(String.fromCharCode(...encrypted));
    }

    static async decryptText(encryptedText, symmetricKey) {
        const encryptedBytes = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
        const decrypted = await this.decryptFile(encryptedBytes, symmetricKey);
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
}

class E2EESession {
    constructor() {
        this.encPrivateKey = null;
        this.encPublicKey = null;
        this.signPrivateKey = null;
        this.signPublicKey = null;
        this.isUnlocked = false;
    }

    /**
     * 
     * @param length the recovery string length, default 32 bytes 
     * @returns Base64 encoded recovery string
     */
    static generateRecoveryString(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array)); // Base 64 encoded
    }

    static storeDeviceKeyInBrowserDB(deviceKey) {
        this.callOnStore((store) => {
            const deviceKeyData = {
                id: 'device_key',
                key: deviceKey
            };
            store.put(deviceKeyData);
        });
    }

    static async getDeviceKeyFromBrowserDB() {
        return new Promise((resolve, reject) => {
            this.callOnStore((store) => {
                const request = store.get('device_key');
                request.onsuccess = function () {
                    if (request.result) {
                        const keyData = request.result.key
                        resolve(keyData);
                    } else {
                        reject('Device key not found in browser DB');
                    }
                };
                request.onerror = function () {
                    reject('Error retrieving device key from browser DB');
                };
            });
        });
    }

    static async setupDataEncryptionAndSigningKeys(recoveryString) {
        // Generate data encryption keys
        const dataEncryptionKeys = await E2EECrypto.generateEncryptionKeyPair();
        const privateKey = dataEncryptionKeys.privateKey;
        const publicKey = dataEncryptionKeys.publicKey;

        // Generate signing keys
        const signKeyPair = await E2EECrypto.generateSigningKeyPair();
        const signPublicKey = signKeyPair.publicKey;
        const signPrivateKey = signKeyPair.privateKey;

        //encrypt private keys with recovery string
        const { salt: encSalt, encryptedKey: encPriv } = await E2EECrypto.encryptPrivateKey(privateKey, recoveryString);
        const { salt: signSalt, encryptedKey: signPriv } = await E2EECrypto.encryptPrivateKey(signPrivateKey, recoveryString);

        // Export public keys
        const encPubPem = await E2EECrypto.exportPublicKey(publicKey);
        const signPubPem = await E2EECrypto.exportPublicKey(signPublicKey);

        // Send to server
        const response = await fetch('/records/api/keys/setup/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCsrfToken()
            },
            body: JSON.stringify({
                enc_public_key: encPubPem,
                enc_encrypted_private_key: encPriv,
                enc_salt: encSalt,
                sign_public_key: signPubPem,
                sign_encrypted_private_key: signPriv,
                sign_salt: signSalt
            })
        });

        if (!response.ok) throw new Error('Failed to setup keys');
    }

    static async setupDevice(dataKeys, signKeys) {

        const privateKey = dataKeys.privateKey;
        const publicKey = dataKeys.publicKey;
        const signPrivateKey = signKeys.privateKey;
        const signPublicKey = signKeys.publicKey;

        //generate device key
        const deviceKey = await E2EECrypto.generateSymmetricKey();

        //encrypt private keys with device key
        const encKeyWithDeviceKey = await E2EECrypto.encryptPrivateKeyWithKey(privateKey, deviceKey);
        const signKeyWithDeviceKey = await E2EECrypto.encryptPrivateKeyWithKey(signPrivateKey, deviceKey);

        //store device key in browser db
        this.storeDeviceKeyInBrowserDB(deviceKey);

        // Send to server
        const response = await fetch('/records/api/keys/setup_device/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCsrfToken()
            },
            body: JSON.stringify({
                enc_encrypted_private_key_device: encKeyWithDeviceKey,
                sign_encrypted_private_key_device: signKeyWithDeviceKey
            })
        });

        if (!response.ok) throw new Error('Failed to setup device keys');
    }

    static async oneTimeSetup(recoveryString) {
        // Generate data encryption keys
        const dataEncryptionKeys = await E2EECrypto.generateEncryptionKeyPair();
        const privateKey = dataEncryptionKeys.privateKey;
        const publicKey = dataEncryptionKeys.publicKey;

        // Generate signing keys
        const signKeyPair = await E2EECrypto.generateSigningKeyPair();
        const signPublicKey = signKeyPair.publicKey;
        const signPrivateKey = signKeyPair.privateKey;

        //generate device key
        const deviceKey = await E2EECrypto.generateSymmetricKey();

        //encrypt private keys with recovery string
        const { salt: encSalt, encryptedKey: encPriv } = await E2EECrypto.encryptPrivateKey(privateKey, recoveryString);
        const { salt: signSalt, encryptedKey: signPriv } = await E2EECrypto.encryptPrivateKey(signPrivateKey, recoveryString);

        //encrypt private keys with device key
        const encKeyWithDeviceKey = await E2EECrypto.encryptPrivateKeyWithKey(privateKey, deviceKey);
        const signKeyWithDeviceKey = await E2EECrypto.encryptPrivateKeyWithKey(signPrivateKey, deviceKey);

        //store device key in browser db
        this.storeDeviceKeyInBrowserDB(deviceKey);

        // Export public keys
        const encPubPem = await E2EECrypto.exportPublicKey(publicKey);
        const signPubPem = await E2EECrypto.exportPublicKey(signPublicKey);

        // Send to server
        const response = await fetch('/records/api/keys/setup/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCsrfToken()
            },
            body: JSON.stringify({
                enc_public_key: encPubPem,
                enc_encrypted_private_key: encPriv,
                enc_salt: encSalt,
                sign_public_key: signPubPem,
                sign_encrypted_private_key: signPriv,
                sign_salt: signSalt,
                enc_encrypted_private_key_device: encKeyWithDeviceKey,
                sign_encrypted_private_key_device: signKeyWithDeviceKey
            })
        });

        if (!response.ok) throw new Error('Failed to setup keys');

    }

    static async demoEncryptDecrypt() {
        const recoveryString = E2EESession.generateRecoveryString();
        console.log("Recovery String:", recoveryString);

        // Generate key pair
        const keyPair = await E2EECrypto.generateEncryptionKeyPair();
        const privateKey = keyPair.privateKey;
        const publicKey = keyPair.publicKey;

        // Export and import public key
        const pubPem = await E2EECrypto.exportPublicKey(publicKey);
        console.log("Exported Public Key PEM:", pubPem);
        const importedPubKey = await E2EECrypto.importPublicKey(pubPem);

        // Encrypt private key with recovery string
        const { salt, encryptedKey } = await E2EECrypto.encryptPrivateKey(privateKey, recoveryString);
        console.log("Encrypted Private Key:", encryptedKey);
        console.log("Salt:", salt);

        // Decrypt private key with recovery string
        const decryptedPrivateKey = await E2EECrypto.decryptPrivateKey(encryptedKey, salt, recoveryString);
        console.log("Decrypted Private Key matches:", decryptedPrivateKey === privateKey);

        // Generate symmetric key
        const symmetricKey = await E2EECrypto.generateSymmetricKey();

        // Encrypt some data
        const data = new TextEncoder().encode("Hello, World!");
        const encryptedData = await E2EECrypto.encryptFile(data, symmetricKey);
        console.log("Encrypted Data:", btoa(String.fromCharCode(...new Uint8Array(encryptedData))));

        // Decrypt the data
        const decryptedData = await E2EECrypto.decryptFile(encryptedData, symmetricKey);
        console.log("Decrypted Data:", new TextDecoder().decode(decryptedData));
    }

    callOnStore(fn_) {

        // This works on all devices/browsers, and uses IndexedDBShim as a final fallback 
        var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

        // Open (or create) the database
        var open = indexedDB.open("HospitalDB", 1);

        // Create the schema
        open.onupgradeneeded = function () {
            var db = open.result;
            var store = db.createObjectStore("KeyStore", { keyPath: "id" });
        };


        open.onsuccess = function () {
            // Start a new transaction
            var db = open.result;
            var tx = db.transaction("KeyStore", "readwrite");
            var store = tx.objectStore("KeyStore");

            fn_(store)


            // Close the db when the transaction is done
            tx.oncomplete = function () {
                db.close();
            };
        }
    }
}