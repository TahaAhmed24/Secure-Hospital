export class SecurityLogger {
    constructor(baseUrl="/logs/security", publicKeyPath=null) {
        this.baseUrl = baseUrl;
        this.csrfToken = this.getCookie("csrftoken");
        this.publicKeyPath = publicKeyPath;
        this.publicKey = null;
        this.initPromise = null;
        
        // Auto-initialize if publicKeyPath is provided
        if (this.publicKeyPath) {
            this.initPromise = this.initialize();
        }
    }

    async initialize() {
        if (this.publicKeyPath && !this.publicKey) {
            await this.loadPublicKeyFromFile(this.publicKeyPath);
        }
    }

    async ensureInitialized() {
        if (this.initPromise) {
            await this.initPromise;
        }
    }

    async loadPublicKeyFromFile(path) {
        try {
            const response = await fetch(path);
            if (!response.ok) {
                throw new Error(`Failed to load public key from ${path}: ${response.status} ${response.statusText}`);
            }
            const pemKey = await response.text();
            await this.importPublicKey(pemKey);
        } catch (err) {
            throw err;
        }
    }

    async importPublicKey(pemKey) {
        // Remove PEM headers and decode base64
        const pemContents = pemKey
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/\s/g, '');
        
        const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
        
        this.publicKey = await crypto.subtle.importKey(
            'spki',
            binaryDer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );
    }

    async encryptPayload(payload) {
        if (!this.publicKey) {
            throw new Error("Public key not initialized. Call initialize() first.");
        }

        const jsonStr = JSON.stringify(payload);
        const encoder = new TextEncoder();
        const data = encoder.encode(jsonStr);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            this.publicKey,
            data
        );

        // Convert to base64 for transmission
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    
    async encryptPayloadSymmeric(payload) {
        const aesKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 }, true, ["encrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(payload));

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, aesKey, encoded
        );

        // Split auth tag (last 16 bytes) from ciphertext
        const ciphertext = encrypted.slice(0, -16);
        const tag = encrypted.slice(-16);

        // Export & encrypt AES key with RSA
        const exportedAes = await crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, this.publicKey, exportedAes
        );

        return {
            encryptedKey: this.arrayBufferToBase64Url(encryptedKey),
            iv: this.arrayBufferToBase64Url(iv),
            tag: this.arrayBufferToBase64Url(tag),
            ciphertext: this.arrayBufferToBase64Url(ciphertext)
        };
    }

    // Helper
    arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    getCookie(name) {
        const cookies = document.cookie.split(";").map(c => c.trim());
        for (const cookie of cookies) {
            if (cookie.startsWith(name + '=')) return decodeURIComponent(cookie.slice(name.length + 1));
        }
        return null;
    }

    async log(payload) {
        try {
            // Wait for initialization if in progress
            await this.ensureInitialized();
            
            console.log(`[SecurityLogger] Public key status: ${this.publicKey ? 'LOADED' : 'NOT LOADED'}`);
            
            // Enforce encryption - fail if public key not initialized
            if (!this.publicKey) {
                console.error("[SecurityLogger] Cannot log: Public key not initialized. Provide publicKeyPath in constructor.");
                return;
            }

            const encryptedPayload = await this.encryptPayloadSymmeric(payload);
            const body = JSON.stringify({ encryptedPayload });

            const res = await fetch(this.baseUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": this.csrfToken
                },
                body: body
            });
            if (!res.ok) {
                console.warn("[SecurityLogger] Logger failed:", await res.text());
            } else {
                console.log("[SecurityLogger] Log sent successfully (encrypted)");
            }
        } catch (err) {
            console.error("[SecurityLogger] Logger error:", err);
        }
    }

    async requestedNewCertificate(username) {
        await this.log({ action: "requestedNewCertificate", username, timestamp: new Date().toISOString() });
    }

    async createdNewCertificate(username) {
        await this.log({ action: "createdNewCertificate", username, timestamp: new Date().toISOString() });
    }

    async unknownLoginAtBegin(username) {
        await this.log({ action: "unknownLogin_beginLogin", username, timestamp: new Date().toISOString() });
    }

    async unknownLoginAtChallenge(username) {
        await this.log({ action: "unknownLogin_challenge", username, timestamp: new Date().toISOString() });
    }

    async unknownLoginAtVerify(username) {
        await this.log({ action: "unknownLogin_verify", username, timestamp: new Date().toISOString() });
    }

    async setupUserKeys(username, details = {}) {
        await this.log({ 
            action: "setupUserKeys", 
            username, 
            details: {
                encryptionKeysGenerated: details.encryptionKeysGenerated || true,
                signatureKeysGenerated: details.signatureKeysGenerated || true,
                ...details
            },
            timestamp: new Date().toISOString() 
        });
    }

    async setupDevice(username, deviceName, deviceId, details = {}) {
        await this.log({ 
            action: "setupDevice", 
            username,
            deviceName,
            deviceId,
            details: {
                deviceKeyGenerated: details.deviceKeyGenerated || true,
                keysEncryptedWithDeviceKey: details.keysEncryptedWithDeviceKey || true,
                userAgent: details.userAgent || navigator.userAgent,
                ...details
            },
            timestamp: new Date().toISOString() 
        });
    }

    async revokeDevice(username, deviceName, deviceId, revokedBy = null) {
        await this.log({ 
            action: "revokeDevice", 
            username,
            deviceName,
            deviceId,
            revokedBy: revokedBy || username, // Who performed the revocation
            timestamp: new Date().toISOString() 
        });
    }
}