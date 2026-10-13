/**
 * A fetch wrapper that automatically logs request metadata.
 *
 * @param {string} url - The URL to fetch
 * @param {RequestInit} fetchOptions - Standard fetch options (method, headers, body, etc.)
 * @param {Object} logOptions - Logging configuration
 * @param {Object} logOptions.logger - The logger instance (SecurityLogger or StandardLogger)
 * @param {string} logOptions.action - The action name for the log entry
 * @param {Object} [logOptions.data={}] - Additional data to include in the log
 * @param {string} [logOptions.username] - Username to include in the log
 * @param {boolean} [logOptions.logOnError=true] - Whether to log on fetch errors
 * @param {boolean} [logOptions.logOnSuccess=true] - Whether to log on successful responses
 * @returns {Promise<Response>} - The fetch response
 *
 * @example
 * import { loggedFetch } from './loggedFetch.js';
 * import { StandardLogger } from './logger_standard.js';
 *
 * const logger = new StandardLogger('/logs/standard', '/shared_keys/public_key.pem');
 *
 * const response = await loggedFetch('/api/files/123', {
 *     method: 'DELETE',
 *     headers: { 'Content-Type': 'application/json' }
 * }, {
 *     logger: logger,
 *     action: 'deleteFile',
 *     username: 'john_doe',
 *     data: { fileId: 123, fileName: 'report.pdf' }
 * });
 */
export async function loggedFetch(url, fetchOptions = {}, logOptions = {}) {
    const {
        logger,
        action,
        data = {},
        username = null,
        logOnError = true,
        logOnSuccess = true
    } = logOptions;

    if (!logger) {
        throw new Error('loggedFetch: logger is required in logOptions');
    }

    if (!action) {
        throw new Error('loggedFetch: action is required in logOptions');
    }

    const method = fetchOptions.method || 'GET';
    const startTime = performance.now();

    // Build base metadata available before the request
    const metadata = {
        action,
        route: url,
        http_method: method.toUpperCase(),
        user_agent: navigator.userAgent,
        timestamp: new Date().toISOString(),
        ...(username && { username })
    };

    let response = null;

    try {
        response = await fetch(url, fetchOptions);

        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);

        // Add response metadata
        metadata.response_status = response.status;
        metadata.response_ok = response.ok;
        metadata.duration_ms = duration;

        // Log successful responses (or non-ok responses that didn't throw)
        if (logOnSuccess || !response.ok) {
            await logger.log({
                ...metadata,
                ...data
            });
        }

        return response;

    } catch (err) {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);

        // Add error metadata
        metadata.duration_ms = duration;
        metadata.error = true;
        metadata.error_message = err.message;
        metadata.error_name = err.name;

        if (logOnError) {
            await logger.log({
                ...metadata,
                ...data
            });
        }

        // Re-throw the error so caller can handle it
        throw err;
    }
}

/**
 * Creates a pre-configured loggedFetch with default options.
 * Useful when you want to reuse the same logger and username across multiple calls.
 *
 * @param {Object} defaults - Default options to apply to all loggedFetch calls
 * @param {Object} defaults.logger - The logger instance
 * @param {string} [defaults.username] - Default username
 * @returns {Function} - A configured loggedFetch function
 *
 * @example
 * import { createLoggedFetch } from './loggedFetch.js';
 * import { StandardLogger } from './logger_standard.js';
 *
 * const logger = new StandardLogger('/logs/standard', '/shared_keys/public_key.pem');
 * const loggedFetch = createLoggedFetch({ logger, username: 'john_doe' });
 *
 * // Now you can use it without specifying logger each time
 * const response = await loggedFetch('/api/files/123', { method: 'GET' }, {
 *     action: 'viewFile',
 *     data: { fileId: 123 }
 * });
 */
export function createLoggedFetch(defaults = {}) {
    return async function(url, fetchOptions = {}, logOptions = {}) {
        return loggedFetch(url, fetchOptions, {
            ...defaults,
            ...logOptions,
            // Merge data objects if both exist
            data: {
                ...(defaults.data || {}),
                ...(logOptions.data || {})
            }
        });
    };
}
