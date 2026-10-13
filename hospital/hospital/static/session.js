class SessionManager {
    constructor() {
        this.encPrivateKey = null;
        this.encPublicKey = null;
        this.signPrivateKey = null;
        this.signPublicKey = null;
        this.isUnlocked = false;
    }

    // Setup new keys (encryption + signing)
    async setupKeys(password) {
        // Generate encryption key pair
        const encKeyPair = await E2EECrypto.generateEncryptionKeyPair();
        this.encPublicKey = encKeyPair.publicKey;
        this.encPrivateKey = encKeyPair.privateKey;

        // Generate signing key pair
        const signKeyPair = await E2EECrypto.generateSigningKeyPair();
        this.signPublicKey = signKeyPair.publicKey;
        this.signPrivateKey = signKeyPair.privateKey;

        // Encrypt private keys with password
        const { salt: encSalt, encryptedKey: encPriv } = await E2EECrypto.encryptPrivateKey(this.encPrivateKey, password);
        const { salt: signSalt, encryptedKey: signPriv } = await E2EECrypto.encryptPrivateKey(this.signPrivateKey, password);

        // Export public keys
        const encPubPem = await E2EECrypto.exportPublicKey(this.encPublicKey);
        const signPubPem = await E2EECrypto.exportPublicKey(this.signPublicKey);

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
        this.isUnlocked = true;
    }

    // Unlock session with password (legacy - for recovery)
    async unlockSession(password) {
        const resp = await fetch('/records/api/keys/me/');
        const data = await resp.json();

        // Decrypt encryption private key
        this.encPrivateKey = await E2EECrypto.decryptPrivateKey(data.enc_encrypted_private_key, data.enc_salt, password);
        this.encPublicKey = await E2EECrypto.importPublicKey(data.enc_public_key);

        // Decrypt signing private key
        this.signPrivateKey = await E2EECrypto.decryptPrivateKey(data.sign_encrypted_private_key, data.sign_salt, password, true);
        this.signPublicKey = await E2EECrypto.importSigningPublicKey(data.sign_public_key);

        this.isUnlocked = true;
    }

    // Auto-unlock using device keys from IndexedDB (preferred method)
    async autoUnlockFromDevice() {
        try {
            // 1. Get current user ID from server for user-specific key storage
            const userId = await this.getCurrentUserId();

            // 2. Get device credentials from IndexedDB (user-specific)
            const deviceId = await this.getDeviceIdFromIndexedDB(userId);
            const deviceKey = await this.getDeviceKeyFromIndexedDB(userId);

            if (!deviceId || !deviceKey) {
                throw new Error('Device not registered. Please use recovery string.');
            }

            // 3. Fetch device-encrypted keys from server
            const response = await fetch(`/records/api/device/keys/?device_id=${deviceId}`);
            if (!response.ok) {
                throw new Error('Device not found or access denied');
            }

            const data = await response.json();

            // 4. Use device key directly (it's already a CryptoKey object, non-extractable)
            // No need to import - the key is retrieved directly from IndexedDB

            // 5. Decrypt private keys with device key
            this.encPrivateKey = await this.decryptPrivateKeyWithDeviceKey(
                data.device_encrypted_enc_private_key,
                deviceKey,
                false
            );

            this.signPrivateKey = await this.decryptPrivateKeyWithDeviceKey(
                data.device_encrypted_sign_private_key,
                deviceKey,
                true
            );

            // 5. Get public keys
            const keysResp = await fetch('/records/api/keys/me/');
            const keysData = await keysResp.json();

            this.encPublicKey = await E2EECrypto.importPublicKey(keysData.enc_public_key);
            this.signPublicKey = await E2EECrypto.importSigningPublicKey(keysData.sign_public_key);

            this.isUnlocked = true;
            return true;

        } catch (error) {
            console.error('Auto-unlock failed:', error);
            throw error;
        }
    }

    // Helper: Decrypt private key with device key
    async decryptPrivateKeyWithDeviceKey(encryptedData, deviceKey, isSigningKey = false) {
        const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            deviceKey,
            encrypted
        );

        return isSigningKey
            ? await E2EECrypto.importSigningPrivateKey(decrypted)
            : await E2EECrypto.importPrivateKey(decrypted);
    }

    // Helper: Get current user ID from server
    async getCurrentUserId() {
        // Try to get from global variable first (set in templates)
        if (window.currentUserId) {
            return window.currentUserId;
        }

        // Fallback: Fetch from server
        const response = await fetch('/records/api/keys/me/');
        const data = await response.json();
        return data.user_id;
    }

    // Helper: Get device ID from IndexedDB (user-specific)
    getDeviceIdFromIndexedDB(userId) {
        return new Promise((resolve) => {
            const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
            const open = indexedDB.open("HospitalDB", 2);

            open.onsuccess = function() {
                const db = open.result;
                if (!db.objectStoreNames.contains("KeyStore")) {
                    db.close();
                    resolve(null);
                    return;
                }

                const tx = db.transaction("KeyStore", "readonly");
                const store = tx.objectStore("KeyStore");
                // Use user-specific key for multi-user support
                const request = store.get(`device_id_${userId}`);

                request.onsuccess = function() {
                    db.close();
                    resolve(request.result ? request.result.value : null);
                };

                request.onerror = function() {
                    db.close();
                    resolve(null);
                };
            };

            open.onerror = function() {
                resolve(null);
            };
        });
    }

    // Helper: Get device key from IndexedDB (user-specific)
    getDeviceKeyFromIndexedDB(userId) {
        return new Promise((resolve) => {
            const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
            const open = indexedDB.open("HospitalDB", 2);

            open.onsuccess = function() {
                const db = open.result;
                if (!db.objectStoreNames.contains("KeyStore")) {
                    db.close();
                    resolve(null);
                    return;
                }

                const tx = db.transaction("KeyStore", "readonly");
                const store = tx.objectStore("KeyStore");
                // Use user-specific key for multi-user support
                const request = store.get(`device_key_${userId}`);

                request.onsuccess = function() {
                    db.close();
                    resolve(request.result ? request.result.key : null);
                };

                request.onerror = function() {
                    db.close();
                    resolve(null);
                };
            };

            open.onerror = function() {
                resolve(null);
            };
        });
    }

    // Getters
    getEncryptionPrivateKey() { 
        if (!this.isUnlocked) throw new Error('Session locked'); 
        return this.encPrivateKey; 
    }

    getEncryptionPublicKey() { 
        if (!this.isUnlocked) throw new Error('Session locked'); 
        return this.encPublicKey; 
    }

    getSigningPrivateKey() { 
        if (!this.isUnlocked) throw new Error('Session locked'); 
        return this.signPrivateKey; 
    }

    getSigningPublicKey() { 
        if (!this.isUnlocked) throw new Error('Session locked'); 
        return this.signPublicKey; 
    }

    // Lock session
    lockSession() { 
        this.encPrivateKey = null;
        this.encPublicKey = null;
        this.signPrivateKey = null;
        this.signPublicKey = null;
        this.isUnlocked = false; 
    }

    // Get CSRF token from DOM
    getCsrfToken() { 
        return document.querySelector('[name=csrfmiddlewaretoken]').value; 
    }
}

// Global session instance
const session = new SessionManager();
