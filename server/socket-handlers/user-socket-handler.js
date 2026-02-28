const { log } = require("../../src/util");
const { checkFullAdmin, ROLES, MONITOR_ROLES, getUserDirectMonitors, assignMonitorToUser, unassignMonitorFromUser } = require("../auth-permissions");
const User = require("../model/user");
const { passwordStrength } = require("check-password-strength");
const TranslatableError = require("../translatable-error");

/**
 * Handlers for user management
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 */
module.exports.userSocketHandler = (socket) => {

    /**
     * List all users (full-admin only)
     */
    socket.on("getUserList", async (callback) => {
        try {
            checkFullAdmin(socket);

            const users = await User.listUsers();

            callback({
                ok: true,
                users,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Add a new user (full-admin only)
     */
    socket.on("addUser", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.username || !data.password) {
                throw new Error("Username and password are required.");
            }

            if (passwordStrength(data.password).value === "Too weak") {
                throw new TranslatableError("passwordTooWeak");
            }

            const validRoles = [ROLES.FULL_ADMIN, ROLES.GROUP_ADMIN, ROLES.GROUP_READONLY, ROLES.MONITOR_ADMIN, ROLES.MONITOR_READONLY];
            if (!validRoles.includes(data.role)) {
                throw new Error("Invalid role specified.");
            }

            const user = await User.createUser(data.username, data.password, data.role, socket.userID);

            log.info("user", `User created: ${user.username} (ID: ${user.id}) by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "successAdded",
                msgi18n: true,
                user: await user.toPublicJSON(),
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
                msgi18n: !!e.msgi18n,
            });
        }
    });

    /**
     * Edit a user (full-admin only)
     */
    socket.on("editUser", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.id) {
                throw new Error("User ID is required.");
            }

            const updates = {};

            if (data.username !== undefined) {
                updates.username = data.username;
            }

            if (data.role !== undefined) {
                const validRoles = [ROLES.FULL_ADMIN, ROLES.GROUP_ADMIN, ROLES.GROUP_READONLY, ROLES.MONITOR_ADMIN, ROLES.MONITOR_READONLY];
                if (!validRoles.includes(data.role)) {
                    throw new Error("Invalid role specified.");
                }
                // Prevent changing your own role
                if (data.id === socket.userID && data.role !== socket.userRole) {
                    throw new Error("You cannot change your own role.");
                }
                updates.role = data.role;
            }

            if (data.active !== undefined) {
                updates.active = data.active;
            }

            const user = await User.updateUser(data.id, updates);

            log.info("user", `User updated: ${user.username} (ID: ${user.id}) by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "Saved.",
                user: await user.toPublicJSON(),
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Reset a user's password (full-admin only)
     */
    socket.on("resetUserPassword", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.id || !data.newPassword) {
                throw new Error("User ID and new password are required.");
            }

            if (passwordStrength(data.newPassword).value === "Too weak") {
                throw new TranslatableError("passwordTooWeak");
            }

            await User.resetPassword(data.id, data.newPassword);

            log.info("user", `Password reset for user ID: ${data.id} by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "Password reset successfully.",
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
                msgi18n: !!e.msgi18n,
            });
        }
    });

    /**
     * Delete a user (full-admin only)
     */
    socket.on("deleteUser", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.id) {
                throw new Error("User ID is required.");
            }

            // Prevent self-deletion
            if (data.id === socket.userID) {
                throw new Error("You cannot delete your own account.");
            }

            await User.deleteUser(data.id);

            log.info("user", `User deleted: ID ${data.id} by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "Deleted.",
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Get direct monitor assignments for a user (full-admin only)
     */
    socket.on("getUserMonitors", async (userID, callback) => {
        try {
            checkFullAdmin(socket);

            const monitors = await getUserDirectMonitors(userID);

            callback({
                ok: true,
                monitors,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Assign a monitor directly to a user (full-admin only)
     */
    socket.on("assignMonitorToUser", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.userID || !data.monitorID) {
                throw new Error("User ID and Monitor ID are required.");
            }

            const validRoles = [MONITOR_ROLES.ADMIN, MONITOR_ROLES.READONLY];
            if (data.role && !validRoles.includes(data.role)) {
                throw new Error("Invalid role. Must be admin or readonly.");
            }

            await assignMonitorToUser(data.userID, data.monitorID, data.role || MONITOR_ROLES.READONLY);

            log.info("user", `Monitor ${data.monitorID} assigned to user ${data.userID} with role ${data.role || MONITOR_ROLES.READONLY} by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "successAdded",
                msgi18n: true,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Remove a direct monitor assignment from a user (full-admin only)
     */
    socket.on("unassignMonitorFromUser", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.userID || !data.monitorID) {
                throw new Error("User ID and Monitor ID are required.");
            }

            await unassignMonitorFromUser(data.userID, data.monitorID);

            log.info("user", `Monitor ${data.monitorID} unassigned from user ${data.userID} by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "Deleted.",
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });
};
