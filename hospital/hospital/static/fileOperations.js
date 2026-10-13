class FileOperations {

    static async uploadFile(file, recipientUserIds, patientId = null) {
        if (!session.isUnlocked) throw new Error('Session locked');

        const fileData = await file.arrayBuffer();
        const symmetricKey = await E2EECrypto.generateSymmetricKey();
        const encryptedFile = await E2EECrypto.encryptFile(fileData, symmetricKey);
        const encryptedFilename = await E2EECrypto.encryptText(file.name, symmetricKey);

        // Sign the file
        const signature = await E2EECrypto.signData(encryptedFile, session.getSigningPrivateKey());

        const accessGrants = [];

        // Self grant
        const selfEncKey = await E2EECrypto.encryptSymmetricKey(symmetricKey, session.getEncryptionPublicKey());
        accessGrants.push({
            user_id: window.currentUserId,
            encrypted_key: selfEncKey,
            encrypted_filename: encryptedFilename
        });

        // Other recipients
        for (const userId of recipientUserIds) {
            const resp = await fetch(`/records/api/keys/user/${userId}/`);
            const data = await resp.json();
            if (!data.public_key) continue; // skip if no key
            const pubKey = await E2EECrypto.importPublicKey(data.public_key, 'RSA-OAEP');
            const encKey = await E2EECrypto.encryptSymmetricKey(symmetricKey, pubKey);
            accessGrants.push({ user_id: userId, encrypted_key: encKey, encrypted_filename: encryptedFilename });
        }

        const formData = new FormData();
        formData.append('encrypted_file', new Blob([encryptedFile]));
        formData.append('metadata', JSON.stringify({
            encrypted_name: encryptedFilename,
            mime_type: file.type,
            signature: btoa(String.fromCharCode(...new Uint8Array(signature)))
        }));
        formData.append('access_grants', JSON.stringify(accessGrants));

        // Add patient_id if provided (for doctor uploads to patient records)
        if (patientId) {
            formData.append('patient_id', patientId);
        }

        const logData = {
            fileName: file.name,
            fileSize: file.size,
            mimeType: file.type,
            recipientCount: recipientUserIds.length,
        }

        if (patientId) {
            logData.patientId = patientId;
        }

        const response = await window.loggedFetch("/records/api/files/upload/", {
            method: 'POST',
            headers: { 'X-CSRFToken': session.getCsrfToken() },
            body: formData
        }, {
            logger: window.securityLogger,
            action: 'uploadFile',
            username: window.currentUsername,
            data: logData,
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) throw new Error('Upload failed');
        return await response.json();
    }

    static async listFiles() {
        const response = await fetch("/records/api/files/list/");
        const data = await response.json();

        if (!session.isUnlocked) {
            // Return files but can't decrypt filenames
            return data.files.map(f => ({
                ...f,
                filename: '[Locked - Unlock session to view]'
            }));
        }

        // Decrypt filenames
        const files = [];
        for (const file of data.files) {
            try {
                // Decrypt symmetric key with encryption private key
                const symmetricKey = await E2EECrypto.decryptSymmetricKey(
                    file.encrypted_symmetric_key,
                    session.getEncryptionPrivateKey()
                );

                // Decrypt filename
                const filename = await E2EECrypto.decryptText(
                    file.encrypted_filename,
                    symmetricKey
                );

                files.push({
                    ...file,
                    filename: filename
                });
            } catch (error) {
                files.push({
                    ...file,
                    filename: '[Error decrypting]'
                });
            }
        }

        return files;
    }


    static async downloadFile(fileId, encryptedSymmetricKey, filename = "", version = 1) {
        if (!session.isUnlocked) throw new Error('Session locked');

        // Fetch encrypted file
        const response = await window.loggedFetch(`/records/api/files/${fileId}/download/`, {}, {
            logger: window.standardLogger,
            action: 'downloadFile',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                fileName: filename,
                version: version,
            },
            logOnSuccess: true,
            logOnError: true
        });
        const encryptedData = await response.arrayBuffer();

        // Decrypt symmetric key
        const symmetricKey = await E2EECrypto.decryptSymmetricKey(
            encryptedSymmetricKey,
            session.getEncryptionPrivateKey()
        );

        // Decrypt file
        // Note: Signature verification is handled by the backend's verify_signature_chain endpoint
        // and displayed on the file view page. Download-time verification doesn't work for
        // chained signatures (v2+) since they include the previous signature.
        return await E2EECrypto.decryptFile(new Uint8Array(encryptedData), symmetricKey);
    }


    static async shareFile(fileId, encryptedSymmetricKey, recipientUserIds) {

        // 1. Decrypt symmetric key
        const symmetricKey = await E2EECrypto.decryptSymmetricKey(
            encryptedSymmetricKey,
            session.getEncryptionPrivateKey()
        );

        // 2. Fetch current file list (to get encrypted filename)
        const files = await this.listFiles();
        const file = files.find(f => f.id === fileId);
        if (!file) throw new Error("File not found locally");
        const encryptedFilename = file.encrypted_filename;

        // 3. Encrypt symmetric key for new recipients
        const accessGrants = [];
        for (const userId of recipientUserIds) {

            const response = await fetch(`/records/api/keys/user/${userId}/`);
            const data = await response.json();
            const recipientPublicKey = await E2EECrypto.importPublicKey(data.public_key);

            const encryptedKey = await E2EECrypto.encryptSymmetricKey(
                symmetricKey,
                recipientPublicKey
            );

            accessGrants.push({
                user_id: userId,
                encrypted_key: encryptedKey,
                encrypted_filename: encryptedFilename
            });
        }

        // 4. Send to Django (security log - access control change)
        const response = await window.loggedFetch(`/records/api/files/${fileId}/share/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
            body: JSON.stringify({ access_grants: accessGrants })
        }, {
            logger: window.securityLogger,
            action: 'shareFile',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                fileName: file.filename,
                recipientCount: recipientUserIds.length
            },
            logOnSuccess: true,
            logOnError: true
        });
        if (!response.ok) throw new Error('Share failed');
        return true;
    }

    static async shareAccess(fileId, fromPatient = true) {
        try {
            // Get users to share with based on role
            let apiUrl = '/records/api/users/';

            // For doctors uploading to a patient's record, get patient + patient's doctors
            if (userRole === 'doctor' && selectedPatientId) {
                apiUrl += `?patient_id=${selectedPatientId}`;
            }

            const usersResponse = await fetch(apiUrl);
            const usersData = await usersResponse.json();

            // Share with returned users (for patients: their doctors, for doctors: patient + patient's doctors)
            const recipientIds = usersData.users.map(u => u.id);

            // Upload file using FileOperations class (pass patient_id for doctor uploads to set pending status)
            const patientIdForUpload = (userRole === 'doctor' && selectedPatientId) ? selectedPatientId : null;
            await FileOperations.uploadFile(file, recipientIds, patientIdForUpload);

            // Log successful upload
            await standardLogger.uploadFile(currentUsername, file.name);

            const successMessage = (userRole === 'doctor' && selectedPatientId)
                ? 'File uploaded! Awaiting patient approval...'
                : 'File uploaded and shared successfully!';
            progress.innerHTML = `<div class="alert alert-success">${successMessage}</div>`;
            fileInput.value = '';

            // Reload files after a short delay
            setTimeout(() => {
                progress.innerHTML = '';
                loadFiles();
            }, 2000);

        } catch (error) {
            await standardLogger.logMessage(`Failed to upload file ${file.name}: ${error.message}`, 'error');
            progress.innerHTML = `<div class="alert alert-danger">Upload failed: ${error.message}</div>`;
        }
    }

    /**
     * Get all versions of a file
     * @param {number} fileId - The file ID
     * @returns {Promise<Object>} Object containing file_id, versions array, and total_versions
     */
    static async listFileVersions(fileId) {
        const response = await fetch(`/records/api/files/${fileId}/versions/`);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list versions');
        }

        return await response.json();
    }

    /**
     * Share access to a specific version with additional users
     * @param {number} fileId - The file ID
     * @param {number} versionId - The version ID
     * @param {string} encryptedSymmetricKey - The encrypted symmetric key for this version (to decrypt and re-encrypt)
     * @param {Array<number>} recipientUserIds - Array of user IDs to share with
     * @param {string} decryptedFilename - The decrypted filename
     * @returns {Promise<Object>} Response with granted_count and message
     */
    static async shareAccessToVersion(fileId, versionId, encryptedSymmetricKey, recipientUserIds, decryptedFilename) {

        // Decrypt the symmetric key
        const symmetricKey = await E2EECrypto.decryptSymmetricKey(
            encryptedSymmetricKey,
            session.getEncryptionPrivateKey()
        );

        // Encrypt filename with the symmetric key
        const encryptedFilename = await E2EECrypto.encryptText(decryptedFilename, symmetricKey);

        // Prepare access grants for new recipients
        const accessGrants = [];
        for (const userId of recipientUserIds) {
            const keyResponse = await fetch(`/records/api/keys/user/${userId}/`);
            const keyData = await keyResponse.json();

            if (!keyData.public_key) continue; // Skip if no key

            const publicKey = await E2EECrypto.importPublicKey(keyData.public_key, 'RSA-OAEP');
            const encryptedKey = await E2EECrypto.encryptSymmetricKey(symmetricKey, publicKey);

            accessGrants.push({
                user_id: userId,
                encrypted_key: encryptedKey,
                encrypted_filename: encryptedFilename
            });
        }

        // Send to backend (security log - access control change)
        const response = await window.loggedFetch(`/records/api/files/${fileId}/versions/${versionId}/share/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
            body: JSON.stringify({ access_grants: accessGrants })
        }, {
            logger: window.securityLogger,
            action: 'shareFileVersion',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                versionId: versionId,
                fileName: decryptedFilename,
                recipientCount: recipientUserIds.length
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to share version access');
        }

        return await response.json();
    }

    /**
     * Share access to all versions of a file with specified users
     * Useful when adding a new doctor to a patient - they get access to entire file history
     * @param {number} fileId - The file ID
     * @param {Array<number>} recipientUserIds - Array of user IDs to share with
     * @returns {Promise<Object>} Response with users_granted, total_grants, and message
     */
    static async shareAccessToAllVersions(fileId, recipientUserIds) {

        // Get all versions of the file (now includes grant data!)
        const versionsData = await this.listFileVersions(fileId);

        // Prepare access grants for each user and each version
        const accessGrants = [];

        for (const userId of recipientUserIds) {
            // Get user's public key
            const keyResponse = await fetch(`/records/api/keys/user/${userId}/`);
            const keyData = await keyResponse.json();

            if (!keyData.public_key) continue; // Skip if no key

            const publicKey = await E2EECrypto.importPublicKey(keyData.public_key, 'RSA-OAEP');

            const versionGrants = [];

            // For each version, use grant data from the version list (no additional fetch needed!)
            for (const version of versionsData.versions) {
                // Skip versions where we don't have access
                if (!version.grant) continue;

                // Decrypt the symmetric key using current user's private key
                const symmetricKey = await E2EECrypto.decryptSymmetricKey(
                    version.grant.encrypted_symmetric_key,
                    session.getEncryptionPrivateKey()
                );

                // Decrypt the filename
                const decryptedFilename = await E2EECrypto.decryptText(
                    version.grant.encrypted_filename,
                    symmetricKey
                );

                // Re-encrypt symmetric key for the new user
                const encryptedKey = await E2EECrypto.encryptSymmetricKey(symmetricKey, publicKey);

                // Re-encrypt filename with the same symmetric key
                const encryptedFilename = await E2EECrypto.encryptText(decryptedFilename, symmetricKey);

                versionGrants.push({
                    version_id: version.id,
                    encrypted_key: encryptedKey,
                    encrypted_filename: encryptedFilename
                });
            }

            accessGrants.push({
                user_id: userId,
                version_grants: versionGrants
            });
        }

        // Send to backend (security log - access control change)
        const response = await window.loggedFetch(`/records/api/files/${fileId}/share-all-versions/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
            body: JSON.stringify({ access_grants: accessGrants })
        }, {
            logger: window.securityLogger,
            action: 'shareAllFileVersions',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                recipientCount: recipientUserIds.length,
                versionCount: versionsData.versions.length
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to share access to all versions');
        }

        return await response.json();
    }

    /**
     * Share all patient files with a newly appointed doctor
     * This gives the doctor access to all versions of all patient files
     * @param {number} doctorUserId - The doctor's user ID
     * @param {number} patientId - The patient's ID (optional, uses current user if not provided)
     * @returns {Promise<Object>} Summary of files and versions shared
     */
    static async shareAllPatientFilesWithDoctor(doctorUserId, patientId = null) {

        if (!session.isUnlocked) {
            await session.autoUnlockFromDevice()
        }

        // Get all files for the patient
        let apiUrl = '/records/api/files/list/';
        if (patientId) {
            apiUrl += `?patient_id=${patientId}`;
        }

        const filesResponse = await fetch(apiUrl);
        if (!filesResponse.ok) throw new Error('Failed to fetch patient files');

        const filesData = await filesResponse.json();
        const files = filesData.files;

        let totalFilesShared = 0;
        let totalVersionsShared = 0;
        const errors = [];

        // For each file, share all versions with the doctor
        for (const file of files) {
            try {
                const result = await this.shareAccessToAllVersions(file.id, [doctorUserId]);
                if (result.success) {
                    totalFilesShared++;
                    totalVersionsShared += result.total_grants;
                }
            } catch (error) {
                errors.push({
                    fileId: file.id,
                    filename: file.filename || 'Unknown',
                    error: error.message
                });
            }
        }

        return {
            success: true,
            total_files: files.length,
            files_shared: totalFilesShared,
            versions_shared: totalVersionsShared,
            errors: errors
        };
    }

    static async revokeAccess(userId) {
        let apiUrl = `/records/api/files/revoke-access/${userId}`;
        const response = await window.loggedFetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
        }, {
            logger: window.securityLogger,
            action: 'revokeFileAccess',
            username: window.currentUsername,
            data: {
                revokedUserId: userId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to revoke access');
        }

        return await response.json();
    }

}

/**
 * Version-specific file operations
 * Handles version creation, approval, rejection, and deletion
 */
class VersionOperations {

    /**
     * Create a new version of an existing file
     * @param {number} fileId - The file ID
     * @param {string} newContent - The new content text
     * @param {string} decryptedFilename - The decrypted filename
     * @param {string} previousSignature - The previous version's signature (base64)
     * @returns {Promise<Object>} The response data
     */
    static async createVersion(fileId, newContent, decryptedFilename, previousSignature) {
        if (!session.isUnlocked) throw new Error('Session locked');

        // FORWARD SECRECY: Generate NEW symmetric key for this version
        const newSymmetricKey = await E2EECrypto.generateSymmetricKey();

        // Encrypt new content with the NEW symmetric key
        const encryptedContent = await E2EECrypto.encryptText(newContent, newSymmetricKey);

        // Convert encrypted content to bytes for signing
        const encryptedBytes = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));

        // SIGNATURE CHAINING: Sign (encrypted_content + previous_signature)
        const previousSigBytes = Uint8Array.from(atob(previousSignature), c => c.charCodeAt(0));
        const dataToSign = new Uint8Array(encryptedBytes.length + previousSigBytes.length);
        dataToSign.set(encryptedBytes, 0);
        dataToSign.set(previousSigBytes, encryptedBytes.length);

        // Sign the chained data
        const signatureBuffer = await E2EECrypto.signData(
            dataToSign,
            session.getSigningPrivateKey()
        );

        // Convert signature to base64
        const signatureBytes = new Uint8Array(signatureBuffer);
        const signatureBase64 = btoa(String.fromCharCode(...signatureBytes));

        // Get list of users with access to current version
        const accessResponse = await fetch(`/records/api/files/${fileId}/access/`);
        const accessData = await accessResponse.json();
        const existingUserIds = new Set(accessData.users);

        // Get all appointed doctors for the patient (to ensure they all have access to new versions)
        const usersResponse = await fetch('/records/api/users/');
        const usersData = await usersResponse.json();
        const appointedDoctorIds = usersData.users.map(u => u.id);

        // Combine existing users with appointed doctors (remove duplicates with Set)
        const allUserIds = new Set([...existingUserIds, ...appointedDoctorIds]);

        // Re-encrypt NEW symmetric key for all users
        const accessGrants = [];
        for (const userId of allUserIds) {
            const keyResponse = await fetch(`/records/api/keys/user/${userId}/`);
            const keyData = await keyResponse.json();

            if (!keyData.public_key) continue;

            const publicKey = await E2EECrypto.importPublicKey(keyData.public_key, 'RSA-OAEP');
            const encryptedKey = await E2EECrypto.encryptSymmetricKey(newSymmetricKey, publicKey);
            const encryptedFilename = await E2EECrypto.encryptText(decryptedFilename, newSymmetricKey);

            accessGrants.push({
                user_id: userId,
                encrypted_key: encryptedKey,
                encrypted_filename: encryptedFilename
            });
        }

        // Create multipart form data
        const encryptedBytes2 = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
        const formData = new FormData();
        formData.append('encrypted_file', new Blob([encryptedBytes2]));
        formData.append('file_id', fileId);
        formData.append('metadata', JSON.stringify({
            signature: signatureBase64
        }));
        formData.append('access_grants', JSON.stringify(accessGrants));

        const response = await window.loggedFetch('/records/api/files/new-version/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': session.getCsrfToken()
            },
            body: formData
        }, {
            logger: window.securityLogger,
            action: 'createVersion',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                fileName: decryptedFilename,
                recipientCount: accessGrants.length
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save version');
        }

        return await response.json();
    }

    /**
     * Download a specific version of a file
     * @param {number} fileId - The file ID
     * @param {string} encryptedSymmetricKey - The encrypted symmetric key for this version
     * @param {string} decryptedFilename - The decrypted filename
     * @param {string} mimeType - The file's MIME type
     * @param {number} version - The version number
     */
    static async downloadVersion(fileId, encryptedSymmetricKey, decryptedFilename, mimeType, version = 1) {
        if (!session.isUnlocked) throw new Error('Session locked');

        const response = await window.loggedFetch(`/records/api/files/${fileId}/download/`, {}, {
            logger: window.standardLogger,
            action: 'downloadFileVersion',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                fileName: decryptedFilename,
                version: version
            },
            logOnSuccess: true,
            logOnError: true
        });
        const encryptedData = await response.arrayBuffer();

        const symmetricKey = await E2EECrypto.decryptSymmetricKey(
            encryptedSymmetricKey,
            session.getEncryptionPrivateKey()
        );

        const decryptedData = await E2EECrypto.decryptFile(
            new Uint8Array(encryptedData),
            symmetricKey
        );

        // Create and trigger download
        const blob = new Blob([decryptedData], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = decryptedFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Approve a pending version (patient only)
     * @param {number} fileId - The file ID
     * @param {number} versionId - The version ID to approve
     */
    static async approveVersion(fileId, versionId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/approve/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
            body: JSON.stringify({ version_id: versionId })
        }, {
            logger: window.securityLogger,
            action: 'approveVersion',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                versionId: versionId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to approve version');
        }

        return await response.json();
    }

    /**
     * Reject a pending version (patient only)
     * @param {number} fileId - The file ID
     * @param {number} versionId - The version ID to reject
     */
    static async rejectVersion(fileId, versionId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/reject/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            },
            body: JSON.stringify({ version_id: versionId })
        }, {
            logger: window.securityLogger,
            action: 'rejectVersion',
            username: window.currentUsername,
            data: {
                fileId: fileId,
                versionId: versionId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to reject version');
        }

        return await response.json();
    }

    /**
     * Delete a file (patient only)
     * @param {number} fileId - The file ID
     */
    static async deleteFile(fileId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/delete/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': session.getCsrfToken()
            }
        }, {
            logger: window.securityLogger,
            action: 'deleteFile',
            username: window.currentUsername,
            data: {
                fileId: fileId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete file');
        }

        return await response.json();
    }

    /**
     * Request deletion of a file (doctor only)
     * @param {number} fileId - The file ID
     */
    static async requestDeletion(fileId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/request-deletion/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': session.getCsrfToken()
            }
        }, {
            logger: window.securityLogger,
            action: 'requestFileDeletion',
            username: window.currentUsername,
            data: {
                fileId: fileId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to request deletion');
        }

        return await response.json();
    }

    /**
     * Approve a deletion request (patient only)
     * @param {number} fileId - The file ID
     */
    static async approveDeletion(fileId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/approve-deletion/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            }
        }, {
            logger: window.securityLogger,
            action: 'approveFileDeletion',
            username: window.currentUsername,
            data: {
                fileId: fileId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to approve deletion');
        }

        return await response.json();
    }

    /**
     * Reject a deletion request (patient only)
     * @param {number} fileId - The file ID
     */
    static async rejectDeletion(fileId) {
        const response = await window.loggedFetch(`/records/api/files/${fileId}/reject-deletion/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': session.getCsrfToken()
            }
        }, {
            logger: window.securityLogger,
            action: 'rejectFileDeletion',
            username: window.currentUsername,
            data: {
                fileId: fileId
            },
            logOnSuccess: true,
            logOnError: true
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to reject deletion');
        }

        return await response.json();
    }
}