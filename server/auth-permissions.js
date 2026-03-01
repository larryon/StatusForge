const { R } = require("redbean-node");

/**
 * Permission roles — simplified to admin (full access) and read-only (view all resources)
 * @readonly
 * @enum {string}
 */
const ROLES = {
    ADMIN: "admin",
    READ_ONLY: "read-only",
};

/**
 * Check if a socket is logged in
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 * @throws {Error} if not logged in
 */
function checkLogin(socket) {
    if (!socket.userID) {
        throw new Error("You are not logged in.");
    }
}

/**
 * Check if the logged-in user is an admin
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 * @throws {Error} if not an admin
 */
function checkAdmin(socket) {
    checkLogin(socket);
    if (socket.userRole !== ROLES.ADMIN) {
        throw new Error("Permission denied. Admin access required.");
    }
}

/**
 * Get the role of a user
 * @param {number} userID ID of the user
 * @returns {Promise<string>} The user's role
 */
async function getUserRole(userID) {
    const user = await R.getRow("SELECT role FROM `user` WHERE id = ? AND active = 1", [userID]);
    if (!user) {
        throw new Error("User not found or inactive.");
    }
    return user.role;
}

/**
 * Assert that the user can edit a monitor, throw if not.
 * Only admins can edit monitors.
 * @param {Socket} socket Socket.io instance
 * @param {number} monitorID ID of monitor (unused, kept for interface compatibility)
 * @returns {void}
 * @throws {Error} Permission denied
 */
function assertCanEditMonitor(socket, monitorID) {
    checkAdmin(socket);
}

/**
 * Assert that the user can view a monitor, throw if not.
 * Both admins and read-only users can view all monitors.
 * @param {Socket} socket Socket.io instance
 * @param {number} monitorID ID of monitor (unused, kept for interface compatibility)
 * @returns {void}
 */
function assertCanAccessMonitor(socket, monitorID) {
    checkLogin(socket);
}

/**
 * Assert that the user can edit a maintenance, throw if not.
 * Only admins can edit maintenances.
 * @param {Socket} socket Socket.io instance
 * @param {object} maintenance Maintenance bean (unused, kept for interface compatibility)
 * @returns {void}
 * @throws {Error} Permission denied
 */
function assertCanEditMaintenance(socket, maintenance) {
    checkAdmin(socket);
}

/**
 * Assert that the user can access a maintenance, throw if not.
 * Both admins and read-only users can view all maintenances.
 * @param {Socket} socket Socket.io instance
 * @param {object} maintenance Maintenance bean (unused, kept for interface compatibility)
 * @returns {void}
 */
function assertCanAccessMaintenance(socket, maintenance) {
    checkLogin(socket);
}

/**
 * Check if a user can create monitors (admin only)
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 * @throws {Error} Permission denied
 */
function checkCanCreateMonitor(socket) {
    checkAdmin(socket);
}

module.exports = {
    ROLES,
    checkLogin,
    checkAdmin,
    getUserRole,
    assertCanEditMonitor,
    assertCanAccessMonitor,
    assertCanEditMaintenance,
    assertCanAccessMaintenance,
    checkCanCreateMonitor,
};
