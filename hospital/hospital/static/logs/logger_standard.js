export class StandardLogger {
    constructor(baseUrl = "/logs/standard", publicKeyPath = null) {
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
                throw new Error(`Failed to load public key from ${path}`);
            }
            const pemKey = await response.text();
            await this.importPublicKey(pemKey);
        } catch (err) {
            console.error("Failed to load public key:", err);
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

            // Enforce encryption - fail if public key not initialized
            if (!this.publicKey) {
                console.error("Cannot log: Public key not initialized. Provide publicKeyPath in constructor.");
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
                console.warn("Logger failed:", await res.text());
            }
        } catch (err) {
            console.error("Logger error:", err);
        }
    }

    async logLogin(username) {
        await this.log({
            action: "login",
            username: username,
            timestamp: new Date().toISOString()
        });
    }

    async logLogout(username) {
        await this.log({
            action: "logout",
            username: username,
            timestamp: new Date().toISOString()
        });
    }

    async logUpdateInfo(username) {
        await this.log({
            action: "updatedInfo",
            username: username,
            timestamp: new Date().toISOString()
        });
    }

    async logMessage(message, level = "info") {
        await this.log({
            action: "message",
            level: level,
            message: message,
            timestamp: new Date().toISOString()
        });
    }

    // ========== Doctor/Patient List Management ==========

    async browseDoctorsList(username) {
        await this.log({
            action: "browseDoctorsList",
            username: username,
            timestamp: new Date().toISOString()
        });
    }

    async browsePatientslist(username) {
        await this.log({
            action: "browsePatientsList",
            username: username,
            timestamp: new Date().toISOString()
        });
    }

    async addDoctorToList(username, doctorId, doctorName) {
        await this.log({
            action: "addDoctorToList",
            username: username,
            doctorId: doctorId,
            doctorName: doctorName,
            timestamp: new Date().toISOString()
        });
    }

    async removeDoctorFromList(username, doctorId, doctorName) {
        await this.log({
            action: "removeDoctorFromList",
            username: username,
            doctorId: doctorId,
            doctorName: doctorName,
            timestamp: new Date().toISOString()
        });
    }

    // ========== Appointment Management ==========

    async requestAppointment(doctorUsername, patientId, appointmentDetails = {}) {
        await this.log({
            action: "requestAppointment",
            patientId: patientId,
            doctorUsername: doctorUsername,
            appointmentId: appointmentDetails.appointmentId,
            proposedDate: appointmentDetails.proposedDate,
            timestamp: new Date().toISOString()
        });
    }

    async approveAppointment(doctorId, doctorUsername, requestId) {
        await this.log({
            action: "approveAppointment",
            doctorId: doctorId,
            doctorUsername: doctorUsername,
            appointmentId: requestId,
            timestamp: new Date().toISOString()
        });
    }

    async declineAppointment(doctorId, doctorUsername, appointmentId) {
        await this.log({
            action: "declineAppointment",
            doctorId: doctorId,
            doctorUsername: doctorUsername,
            appointmentId: appointmentId,
            timestamp: new Date().toISOString()
        });
    }

    async viewSingleFile(username, fileId, fileName) {
        await this.log({ action: "viewSingleFile", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async downloadFile(username, fileId, fileName) {
        await this.log({ action: "downloadFile", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async editFileContent(username, fileId, fileName) {
        await this.log({ action: "editFileContent", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async requestEdit(username, fileId, fileName, ownerUsername = null) {
        await this.log({ action: "requestEdit", username, fileId, fileName, ownerUsername, timestamp: new Date().toISOString() });
    }

    async approveEdit(username, editorUsername, fileId, fileName) {
        await this.log({ action: "approveEdit", username, editorUsername, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async declineEdit(username, editorUsername, fileId, fileName, reason = null) {
        await this.log({ action: "declineEdit", username, editorUsername, fileId, fileName, reason, timestamp: new Date().toISOString() });
    }

    async deleteFile(username, fileId, fileName) {
        await this.log({ action: "deleteFile", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async uploadFile(username, fileName) {
        await this.log({ action: "uploadFile", username, fileName, timestamp: new Date().toISOString() });
    }

    async requestFileDeletion(username, fileId, fileName) {
        await this.log({ action: "requestFileDeletion", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async approveFileDeletion(username, fileId, fileName) {
        await this.log({ action: "approveFileDeletion", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async rejectFileDeletion(username, fileId, fileName) {
        await this.log({ action: "rejectFileDeletion", username, fileId, fileName, timestamp: new Date().toISOString() });
    }

    async verifySignature(fileId, valid) {
        await this.log({ action: "verifySignature", fileId, valid, timestamp: new Date().toISOString() });
    }
}