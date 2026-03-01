const { R } = require("redbean-node");
const { log } = require("../../src/util");
const passwordHash = require("../password-hash");
const dayjs = require("dayjs");
const { ROLES } = require("../auth-permissions");
const { apiRateLimiter } = require("../rate-limiter");

/**
 * All available API permission scopes.
 * Keys are scoped as "resource:action".
 * @readonly
 * @enum {string}
 */
const API_SCOPES = {
    // Monitors
    MONITORS_READ: "monitors:read",
    MONITORS_WRITE: "monitors:write",

    // Notifications
    NOTIFICATIONS_READ: "notifications:read",
    NOTIFICATIONS_WRITE: "notifications:write",

    // Status pages
    STATUS_PAGES_READ: "status-pages:read",
    STATUS_PAGES_WRITE: "status-pages:write",

    // Maintenance
    MAINTENANCE_READ: "maintenance:read",
    MAINTENANCE_WRITE: "maintenance:write",

    // Tags
    TAGS_READ: "tags:read",
    TAGS_WRITE: "tags:write",

    // Users (admin only)
    USERS_READ: "users:read",
    USERS_WRITE: "users:write",

    // API keys
    API_KEYS_READ: "api-keys:read",
    API_KEYS_WRITE: "api-keys:write",

    // Uptime / heartbeats
    UPTIME_READ: "uptime:read",

    // Docker hosts
    DOCKER_READ: "docker:read",
    DOCKER_WRITE: "docker:write",

    // General settings (admin only)
    SETTINGS_READ: "settings:read",
    SETTINGS_WRITE: "settings:write",
};

/**
 * Scope groups for convenience when creating keys
 * @type {{[key: string]: string[]}}
 */
const SCOPE_GROUPS = {
    "read-only": [
        API_SCOPES.MONITORS_READ,
        API_SCOPES.NOTIFICATIONS_READ,
        API_SCOPES.STATUS_PAGES_READ,
        API_SCOPES.MAINTENANCE_READ,
        API_SCOPES.TAGS_READ,
        API_SCOPES.UPTIME_READ,
        API_SCOPES.DOCKER_READ,
    ],
    "read-write": [
        API_SCOPES.MONITORS_READ,
        API_SCOPES.MONITORS_WRITE,
        API_SCOPES.NOTIFICATIONS_READ,
        API_SCOPES.NOTIFICATIONS_WRITE,
        API_SCOPES.STATUS_PAGES_READ,
        API_SCOPES.STATUS_PAGES_WRITE,
        API_SCOPES.MAINTENANCE_READ,
        API_SCOPES.MAINTENANCE_WRITE,
        API_SCOPES.TAGS_READ,
        API_SCOPES.TAGS_WRITE,
        API_SCOPES.UPTIME_READ,
        API_SCOPES.DOCKER_READ,
        API_SCOPES.DOCKER_WRITE,
    ],
    "full-access": Object.values(API_SCOPES),
};

/**
 * Scopes that require admin role on the owning user.
 * Even if the scope is on the key, the user must be admin.
 * @type {Set<string>}
 */
const ADMIN_ONLY_SCOPES = new Set([
    API_SCOPES.USERS_READ,
    API_SCOPES.USERS_WRITE,
    API_SCOPES.SETTINGS_READ,
    API_SCOPES.SETTINGS_WRITE,
]);

/**
 * Verify an API key string and return the owning user + resolved scopes.
 * Key format: uk{id}_{clearTextKey}
 * @param {string} key Raw API key string
 * @returns {Promise<object|null>} { user, apiKey, scopes } or null if invalid
 */
async function resolveAPIKey(key) {
    if (typeof key !== "string" || !key.startsWith("uk")) {
        return null;
    }

    const underscoreIndex = key.indexOf("_");
    if (underscoreIndex === -1) {
        return null;
    }

    const idStr = key.substring(2, underscoreIndex);
    const clearKey = key.substring(underscoreIndex + 1);

    const apiKeyBean = await R.findOne("api_key", " id = ? ", [idStr]);
    if (!apiKeyBean) {
        return null;
    }

    // Check expiry
    if (apiKeyBean.expires) {
        const expiry = dayjs(apiKeyBean.expires);
        if (expiry.diff(dayjs()) < 0) {
            return null;
        }
    }

    // Check active
    if (!apiKeyBean.active) {
        return null;
    }

    // Verify hash
    if (!passwordHash.verify(clearKey, apiKeyBean.key)) {
        return null;
    }

    // Load owner user
    const user = await R.findOne("user", " id = ? AND active = 1 ", [apiKeyBean.user_id]);
    if (!user) {
        return null;
    }

    // Resolve scopes: if permissions column is set, use it; otherwise inherit all from role
    let scopes;
    if (apiKeyBean.permissions) {
        try {
            scopes = JSON.parse(apiKeyBean.permissions);
        } catch (e) {
            log.warn("api-auth", `Invalid permissions JSON for API key ${apiKeyBean.id}: ${e.message}`);
            scopes = [];
        }
    } else {
        // Inherit all scopes based on user role
        scopes = getScopesForRole(user.role);
    }

    // Filter out admin-only scopes if user is not admin
    if (user.role !== ROLES.ADMIN) {
        scopes = scopes.filter(s => !ADMIN_ONLY_SCOPES.has(s));
    }

    return { user, apiKey: apiKeyBean, scopes };
}

/**
 * Get the default scopes available for a given user role.
 * @param {string} role User role from ROLES enum
 * @returns {string[]} Array of scopes
 */
function getScopesForRole(role) {
    switch (role) {
        case ROLES.ADMIN:
            return [...SCOPE_GROUPS["full-access"]];
        case ROLES.READ_ONLY:
            return [...SCOPE_GROUPS["read-only"]];
        default:
            return [...SCOPE_GROUPS["read-only"]];
    }
}

/**
 * Express middleware: authenticate via API key in Authorization header.
 * Supports: "Bearer uk..." or "ApiKey uk..." or raw header value.
 * Sets req.apiUser, req.apiKeyBean, req.apiScopes, req.userRole on success.
 * @param {import("express").Request} req Express request
 * @param {import("express").Response} res Express response
 * @param {import("express").NextFunction} next Next middleware
 * @returns {Promise<void>}
 */
async function apiKeyAuth(req, res, next) {
    // Rate limit
    const pass = await apiRateLimiter.pass(null, 0);
    if (!pass) {
        log.warn("api-auth", "API rate limit exceeded");
        return res.status(429).json({ ok: false, msg: "Rate limit exceeded. Try again later." });
    }
    apiRateLimiter.removeTokens(1);

    // Extract key from Authorization header
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
        return res.status(401).json({ ok: false, msg: "Missing Authorization header. Use: Authorization: Bearer uk..." });
    }

    let rawKey = authHeader;
    if (authHeader.startsWith("Bearer ")) {
        rawKey = authHeader.substring(7);
    } else if (authHeader.startsWith("ApiKey ")) {
        rawKey = authHeader.substring(7);
    }

    const result = await resolveAPIKey(rawKey.trim());
    if (!result) {
        log.warn("api-auth", "Failed API key auth attempt");
        return res.status(401).json({ ok: false, msg: "Invalid or expired API key." });
    }

    // Attach to request
    req.apiUser = result.user;
    req.apiKeyBean = result.apiKey;
    req.apiScopes = new Set(result.scopes);
    req.userRole = result.user.role;

    next();
}

/**
 * Create a scope-checking middleware.
 * Returns 403 if the API key does not have the required scope.
 * @param {string} requiredScope Scope string from API_SCOPES
 * @returns {Function} Express middleware
 */
function requireScope(requiredScope) {
    /**
     * Express middleware that checks for a required API scope
     * @param {import("express").Request} req Express request
     * @param {import("express").Response} res Express response
     * @param {import("express").NextFunction} next Next middleware
     * @returns {void}
     */
    return (req, res, next) => {
        if (!req.apiScopes || !req.apiScopes.has(requiredScope)) {
            return res.status(403).json({
                ok: false,
                msg: `Insufficient permissions. Required scope: ${requiredScope}`,
            });
        }
        next();
    };
}

/**
 * Middleware: require admin role on the API key owner.
 * @param {import("express").Request} req Express request
 * @param {import("express").Response} res Express response
 * @param {import("express").NextFunction} next Next middleware
 * @returns {void}
 */
function requireAdmin(req, res, next) {
    if (!req.apiUser || req.userRole !== ROLES.ADMIN) {
        return res.status(403).json({ ok: false, msg: "This endpoint requires admin privileges." });
    }
    next();
}

/**
 * Check if the API key owner can access a specific monitor.
 * Both admins and read-only users can access all monitors.
 * @param {import("express").Request} req Express request with apiUser attached
 * @param {number} monitorID Monitor ID to check (unused, all monitors accessible)
 * @returns {boolean} true always
 */
function apiCanAccessMonitor(req, monitorID) {
    return true;
}

/**
 * Check if the API key owner can edit a specific monitor.
 * Only admins can edit monitors.
 * @param {import("express").Request} req Express request with apiUser attached
 * @param {number} monitorID Monitor ID to check (unused, admin check only)
 * @returns {boolean} true if admin
 */
function apiCanEditMonitor(req, monitorID) {
    return req.userRole === ROLES.ADMIN;
}

/**
 * Get all monitor IDs accessible via this API key's owner.
 * All users can see all monitors, so always returns null (meaning all).
 * @param {import("express").Request} req Express request with apiUser attached
 * @returns {null} null = all monitors
 */
function apiGetAccessibleMonitorIDs(req) {
    return null;
}

module.exports = {
    API_SCOPES,
    SCOPE_GROUPS,
    ADMIN_ONLY_SCOPES,
    resolveAPIKey,
    getScopesForRole,
    apiKeyAuth,
    requireScope,
    requireAdmin,
    apiCanAccessMonitor,
    apiCanEditMonitor,
    apiGetAccessibleMonitorIDs,
};
