const { log } = require("../../src/util");
const { checkAdmin, ROLES } = require("../auth-permissions");
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
     * List all users (admin only)
     */
    socket.on("getUserList", async (callback) => {
        try {
            checkAdmin(socket);

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
     * Add a new user (admin only)
     */
    socket.on("addUser", async (data, callback) => {
        try {
            checkAdmin(socket);

            if (!data.username || !data.password) {
                throw new Error("Username and password are required.");
            }

            if (passwordStrength(data.password).value === "Too weak") {
                throw new TranslatableError("passwordTooWeak");
            }

            const validRoles = [ROLES.ADMIN, ROLES.READ_ONLY];
            if (!validRoles.includes(data.role)) {
                throw new Error("Invalid role specified.");
            }

            const user = await User.createUser(data.username, data.password, data.role, socket.userID);

            log.info("user", `User created: ${user.username} (ID: ${user.id}) by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "successAdded",
                msgi18n: true,
                user: user.toPublicJSON(),
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
     * Edit a user (admin only)
     */
    socket.on("editUser", async (data, callback) => {
        try {
            checkAdmin(socket);

            if (!data.id) {
                throw new Error("User ID is required.");
            }

            const updates = {};

            if (data.username !== undefined) {
                updates.username = data.username;
            }

            if (data.role !== undefined) {
                const validRoles = [ROLES.ADMIN, ROLES.READ_ONLY];
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
                user: user.toPublicJSON(),
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Reset a user's password (admin only)
     */
    socket.on("resetUserPassword", async (data, callback) => {
        try {
            checkAdmin(socket);

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
     * Delete a user (admin only)
     */
    socket.on("deleteUser", async (data, callback) => {
        try {
            checkAdmin(socket);

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
};
