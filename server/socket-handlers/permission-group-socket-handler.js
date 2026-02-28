const { log } = require("../../src/util");
const { checkFullAdmin, ROLES, getGroupMonitors, assignMonitorToGroup, unassignMonitorFromGroup, canEditInGroup } = require("../auth-permissions");
const { checkLogin } = require("../util-server");
const PermissionGroup = require("../model/permission_group");

/**
 * Handlers for permission group management
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 */
module.exports.permissionGroupSocketHandler = (socket) => {

    /**
     * List permission groups (full-admin sees all, group-admin sees own groups)
     */
    socket.on("getPermissionGroupList", async (callback) => {
        try {
            checkLogin(socket);

            let groups;
            if (socket.userRole === ROLES.FULL_ADMIN) {
                groups = await PermissionGroup.list();
            } else {
                // Non-admins see only groups they belong to
                groups = await PermissionGroup.listForUser(socket.userID);
            }

            callback({
                ok: true,
                groups,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Add a new permission group (full-admin only)
     */
    socket.on("addPermissionGroup", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.name) {
                throw new Error("Group name is required.");
            }

            const group = await PermissionGroup.create(data.name, data.description || "");

            log.info("permission-group", `Permission group created: ${group.name} (ID: ${group.id}) by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "successAdded",
                msgi18n: true,
                group: await group.toJSON(),
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Edit a permission group (full-admin only)
     */
    socket.on("editPermissionGroup", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.id) {
                throw new Error("Group ID is required.");
            }

            const updates = {};
            if (data.name !== undefined) {
                updates.name = data.name;
            }
            if (data.description !== undefined) {
                updates.description = data.description;
            }
            if (data.active !== undefined) {
                updates.active = data.active;
            }

            const group = await PermissionGroup.update(data.id, updates);

            log.info("permission-group", `Permission group updated: ${group.name} (ID: ${group.id}) by user ID: ${socket.userID}`);

            callback({
                ok: true,
                msg: "Saved.",
                group: await group.toJSON(),
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Delete a permission group (full-admin only)
     */
    socket.on("deletePermissionGroup", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.id) {
                throw new Error("Group ID is required.");
            }

            await PermissionGroup.delete(data.id);

            log.info("permission-group", `Permission group deleted: ID ${data.id} by user ID: ${socket.userID}`);

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
     * Get members of a permission group (full-admin or group-admin of this group)
     */
    socket.on("getPermissionGroupMembers", async (groupID, callback) => {
        try {
            checkLogin(socket);

            // Allow full-admin or group-admin of this group
            if (socket.userRole !== ROLES.FULL_ADMIN) {
                const isGroupAdmin = await canEditInGroup(socket.userID, groupID, socket.userRole);
                if (!isGroupAdmin) {
                    throw new Error("Permission denied. You must be a full-admin or group-admin of this group.");
                }
            }

            const members = await PermissionGroup.getMembers(groupID);

            callback({
                ok: true,
                members,
            });
        } catch (e) {
            callback({
                ok: false,
                msg: e.message,
            });
        }
    });

    /**
     * Add a member to a permission group (full-admin or group-admin of the target group)
     */
    socket.on("addPermissionGroupMember", async (data, callback) => {
        try {
            checkLogin(socket);

            // Allow full-admin or group-admin of this group
            if (socket.userRole !== ROLES.FULL_ADMIN) {
                const isGroupAdmin = await canEditInGroup(socket.userID, data.groupID, socket.userRole);
                if (!isGroupAdmin) {
                    throw new Error("Permission denied. You must be a full-admin or group-admin of this group.");
                }
            }

            if (!data.userID || !data.groupID) {
                throw new Error("User ID and Group ID are required.");
            }

            const validRoles = [ROLES.GROUP_ADMIN, ROLES.GROUP_READONLY];
            if (data.role && !validRoles.includes(data.role)) {
                throw new Error("Invalid group role specified. Must be group-admin or group-readonly.");
            }

            await PermissionGroup.addMember(data.userID, data.groupID, data.role || ROLES.GROUP_READONLY);

            log.info("permission-group", `User ${data.userID} added to group ${data.groupID} with role ${data.role || ROLES.GROUP_READONLY} by user ID: ${socket.userID}`);

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
     * Remove a member from a permission group (full-admin or group-admin of the target group)
     */
    socket.on("removePermissionGroupMember", async (data, callback) => {
        try {
            checkLogin(socket);

            // Allow full-admin or group-admin of this group
            if (socket.userRole !== ROLES.FULL_ADMIN) {
                const isGroupAdmin = await canEditInGroup(socket.userID, data.groupID, socket.userRole);
                if (!isGroupAdmin) {
                    throw new Error("Permission denied. You must be a full-admin or group-admin of this group.");
                }
            }

            if (!data.userID || !data.groupID) {
                throw new Error("User ID and Group ID are required.");
            }

            await PermissionGroup.removeMember(data.userID, data.groupID);

            log.info("permission-group", `User ${data.userID} removed from group ${data.groupID} by user ID: ${socket.userID}`);

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
     * Get monitors assigned to a permission group (full-admin only)
     */
    socket.on("getPermissionGroupMonitors", async (groupID, callback) => {
        try {
            checkFullAdmin(socket);

            const monitors = await getGroupMonitors(groupID);

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
     * Assign a monitor to a permission group (full-admin only)
     */
    socket.on("assignMonitorToPermissionGroup", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.monitorID || !data.groupID) {
                throw new Error("Monitor ID and Group ID are required.");
            }

            await assignMonitorToGroup(data.monitorID, data.groupID);

            log.info("permission-group", `Monitor ${data.monitorID} assigned to group ${data.groupID} by user ID: ${socket.userID}`);

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
     * Remove a monitor from a permission group (full-admin only)
     */
    socket.on("unassignMonitorFromPermissionGroup", async (data, callback) => {
        try {
            checkFullAdmin(socket);

            if (!data.monitorID) {
                throw new Error("Monitor ID is required.");
            }

            await unassignMonitorFromGroup(data.monitorID);

            log.info("permission-group", `Monitor ${data.monitorID} removed from permission group by user ID: ${socket.userID}`);

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
