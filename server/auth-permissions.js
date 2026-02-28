const { R } = require("redbean-node");
const { log } = require("../src/util");

/**
 * Permission roles
 * @readonly
 * @enum {string}
 */
const ROLES = {
    FULL_ADMIN: "full-admin",
    GROUP_ADMIN: "group-admin",
    GROUP_READONLY: "group-readonly",
    MONITOR_ADMIN: "monitor-admin",
    MONITOR_READONLY: "monitor-read-only",
};

/**
 * Direct monitor assignment roles
 * @readonly
 * @enum {string}
 */
const MONITOR_ROLES = {
    ADMIN: "admin",
    READONLY: "readonly",
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
 * Check if the logged-in user is a full-admin
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 * @throws {Error} if not a full-admin
 */
function checkFullAdmin(socket) {
    checkLogin(socket);
    if (socket.userRole !== ROLES.FULL_ADMIN) {
        throw new Error("Permission denied. Full-Admin access required.");
    }
}

/**
 * Get the global role of a user
 * @param {number} userID ID of the user
 * @returns {Promise<string>} The user's global role
 */
async function getUserRole(userID) {
    const user = await R.getRow("SELECT role FROM `user` WHERE id = ? AND active = 1", [userID]);
    if (!user) {
        throw new Error("User not found or inactive.");
    }
    return user.role;
}

/**
 * Get a user's role in a specific permission group
 * @param {number} userID ID of the user
 * @param {number} permissionGroupId ID of the permission group
 * @returns {Promise<string|null>} The user's role in the group, or null if not a member
 */
async function getUserGroupRole(userID, permissionGroupId) {
    const row = await R.getRow(
        "SELECT role FROM user_permission_group WHERE user_id = ? AND permission_group_id = ?",
        [userID, permissionGroupId]
    );
    return row ? row.role : null;
}

/**
 * Get all permission groups and roles for a user
 * @param {number} userID ID of the user
 * @returns {Promise<object[]>} Array of {groupId, groupName, role}
 */
async function getUserPermissionGroups(userID) {
    const rows = await R.getAll(
        `SELECT upg.permission_group_id AS groupId, pg.name AS groupName, upg.role
         FROM user_permission_group upg
         JOIN permission_group pg ON pg.id = upg.permission_group_id
         WHERE upg.user_id = ? AND pg.active = 1`,
        [userID]
    );
    return rows;
}

/**
 * Get all monitor IDs that a user can access, considering:
 * 1. Direct user_monitor assignments
 * 2. Permission group membership (monitor.permission_group_id)
 * 3. Parent inheritance: if a "group"-type parent monitor is accessible, all children are too
 * For monitor-level roles (monitor-admin, monitor-read-only), only direct assignments are returned
 * without walking up the parent chain, so monitors appear as a flat list.
 * @param {number} userID ID of the user
 * @param {string} userRole The user's global role (looked up if not provided)
 * @returns {Promise<Set<number>>} Set of accessible monitor IDs
 */
async function getAccessibleMonitorIDs(userID, userRole) {
    // Determine if this is a monitor-level role (flat access, no parent walk-up)
    if (!userRole) {
        try {
            userRole = await getUserRole(userID);
        } catch (e) {
            userRole = null;
        }
    }
    const isMonitorLevelRole = userRole === ROLES.MONITOR_ADMIN || userRole === ROLES.MONITOR_READONLY;
    // 1. Monitors directly assigned via user_monitor
    const directRows = await R.getAll(
        "SELECT monitor_id FROM user_monitor WHERE user_id = ?",
        [userID]
    );

    // 2. Monitors assigned via permission groups
    const pgRows = await R.getAll(
        `SELECT m.id AS monitor_id FROM monitor m
         JOIN user_permission_group upg ON upg.permission_group_id = m.permission_group_id
         WHERE upg.user_id = ? AND m.permission_group_id IS NOT NULL`,
        [userID]
    );

    const accessibleIDs = new Set();
    for (const r of directRows) {
        accessibleIDs.add(r.monitor_id);
    }
    for (const r of pgRows) {
        accessibleIDs.add(r.monitor_id);
    }

    // 3. Upward parent inheritance: walk UP the parent chain for directly accessible monitors
    // so the frontend tree can render them (a child with parent=X won't display unless X is in the list)
    // Skip for monitor-level roles — they get a flat list, parent is nulled out in getMonitorJSONList
    if (accessibleIDs.size > 0 && !isMonitorLevelRole) {
        const idsToResolve = [...accessibleIDs];
        const resolved = new Set();
        for (const mid of idsToResolve) {
            let currentID = mid;
            let depth = 0;
            while (currentID && depth < MAX_PARENT_DEPTH) {
                if (resolved.has(currentID)) {
                    break;
                }
                resolved.add(currentID);
                const row = await R.getRow("SELECT parent FROM monitor WHERE id = ?", [currentID]);
                if (row && row.parent) {
                    accessibleIDs.add(row.parent);
                    currentID = row.parent;
                } else {
                    break;
                }
                depth++;
            }
        }
    }

    // 4. Downward inheritance: find "group"-type monitors in accessible set, add their children
    // Uses a recursive CTE to resolve nested groups in a single query
    // Skip for monitor-level roles — they only see directly assigned monitors
    if (accessibleIDs.size > 0 && !isMonitorLevelRole) {
        const idList = [...accessibleIDs];
        const placeholders = idList.map(() => "?").join(",");
        const parentGroups = await R.getAll(
            `SELECT id FROM monitor WHERE type = 'group' AND id IN (${placeholders})`,
            idList
        );

        if (parentGroups.length > 0) {
            const parentIDs = parentGroups.map(p => p.id);
            const pp = parentIDs.map(() => "?").join(",");
            const descendants = await R.getAll(
                `WITH RECURSIVE children(id, type) AS (
                    SELECT id, type FROM monitor WHERE parent IN (${pp})
                    UNION ALL
                    SELECT m.id, m.type FROM monitor m
                    JOIN children c ON m.parent = c.id
                    WHERE c.type = 'group'
                )
                SELECT id FROM children`,
                parentIDs
            );
            for (const row of descendants) {
                accessibleIDs.add(row.id);
            }
        }
    }

    return accessibleIDs;
}

/** @type {number} Maximum recursion depth for parent traversal to prevent infinite loops */
const MAX_PARENT_DEPTH = 10;

/**
 * Check if a user can access a specific monitor (view).
 * Access is granted if:
 * 1. User is a full-admin
 * 2. User has direct assignment via user_monitor
 * 3. Monitor is in one of the user's permission groups
 * 4. Monitor's parent (group-type) is accessible via 2 or 3
 * @param {number} userID ID of the user
 * @param {number} monitorID ID of the monitor
 * @param {string} userRole The user's global role
 * @param {number} depth Current recursion depth
 * @returns {Promise<boolean>} true if the user can access the monitor
 */
async function canAccessMonitor(userID, monitorID, userRole, depth = 0) {
    if (userRole === ROLES.FULL_ADMIN) {
        return true;
    }

    if (depth > MAX_PARENT_DEPTH) {
        log.warn("auth", `Max parent traversal depth reached for monitor ${monitorID}. Possible circular reference.`);
        return false;
    }

    // Direct assignment
    const direct = await R.getRow(
        "SELECT id FROM user_monitor WHERE user_id = ? AND monitor_id = ?",
        [userID, monitorID]
    );
    if (direct) {
        return true;
    }

    // Permission group assignment
    const pgAccess = await R.getRow(
        `SELECT m.id FROM monitor m
         JOIN user_permission_group upg ON upg.permission_group_id = m.permission_group_id
         WHERE m.id = ? AND upg.user_id = ?`,
        [monitorID, userID]
    );
    if (pgAccess) {
        return true;
    }

    // Parent inheritance: walk up the parent chain
    const monitor = await R.getRow("SELECT parent FROM monitor WHERE id = ?", [monitorID]);
    if (monitor && monitor.parent) {
        return await canAccessMonitor(userID, monitor.parent, userRole, depth + 1);
    }

    return false;
}

/**
 * Check if a user can edit a specific monitor.
 * Requires full-admin, group-admin in permission group, or admin role in direct assignment.
 * @param {number} userID ID of the user
 * @param {number} monitorID ID of the monitor
 * @param {string} userRole The user's global role
 * @param {number} depth Current recursion depth
 * @returns {Promise<boolean>} true if the user can edit the monitor
 */
async function canEditMonitor(userID, monitorID, userRole, depth = 0) {
    if (userRole === ROLES.FULL_ADMIN) {
        return true;
    }

    if (depth > MAX_PARENT_DEPTH) {
        log.warn("auth", `Max parent traversal depth reached for monitor ${monitorID}. Possible circular reference.`);
        return false;
    }

    // Direct assignment with admin role
    const direct = await R.getRow(
        "SELECT id FROM user_monitor WHERE user_id = ? AND monitor_id = ? AND role = ?",
        [userID, monitorID, MONITOR_ROLES.ADMIN]
    );
    if (direct) {
        return true;
    }

    // Permission group with group-admin role
    const pgAccess = await R.getRow(
        `SELECT m.id FROM monitor m
         JOIN user_permission_group upg ON upg.permission_group_id = m.permission_group_id
         WHERE m.id = ? AND upg.user_id = ? AND upg.role = ?`,
        [monitorID, userID, ROLES.GROUP_ADMIN]
    );
    if (pgAccess) {
        return true;
    }

    // Parent inheritance: walk up the parent chain
    const monitor = await R.getRow("SELECT parent FROM monitor WHERE id = ?", [monitorID]);
    if (monitor && monitor.parent) {
        return await canEditMonitor(userID, monitor.parent, userRole, depth + 1);
    }

    return false;
}

/**
 * Check if a user can access a resource by its permission group
 * @param {number} userID ID of the user
 * @param {number} permissionGroupId Permission group ID of the resource
 * @param {string} userRole The user's global role
 * @returns {Promise<boolean>} true if the user can access the resource
 */
async function canAccessGroup(userID, permissionGroupId, userRole) {
    if (userRole === ROLES.FULL_ADMIN) {
        return true;
    }

    if (!permissionGroupId) {
        return false;
    }

    const row = await R.getRow(
        "SELECT id FROM user_permission_group WHERE user_id = ? AND permission_group_id = ?",
        [userID, permissionGroupId]
    );
    return !!row;
}

/**
 * Check if a user can edit resources in a permission group (requires group-admin)
 * @param {number} userID ID of the user
 * @param {number} permissionGroupId Permission group ID
 * @param {string} userRole The user's global role
 * @returns {Promise<boolean>} true if the user can edit resources in the group
 */
async function canEditInGroup(userID, permissionGroupId, userRole) {
    if (userRole === ROLES.FULL_ADMIN) {
        return true;
    }

    if (!permissionGroupId) {
        return false;
    }

    const row = await R.getRow(
        "SELECT id FROM user_permission_group WHERE user_id = ? AND permission_group_id = ? AND role = ?",
        [userID, permissionGroupId, ROLES.GROUP_ADMIN]
    );
    return !!row;
}

/**
 * Get the list of permission group IDs a user has access to
 * @param {number} userID ID of the user
 * @returns {Promise<number[]>} Array of permission group IDs
 */
async function getUserGroupIDs(userID) {
    const rows = await R.getAll(
        "SELECT permission_group_id FROM user_permission_group WHERE user_id = ?",
        [userID]
    );
    return rows.map(r => r.permission_group_id);
}

/**
 * Get direct monitor assignments for a user
 * @param {number} userID ID of the user
 * @returns {Promise<object[]>} Array of {monitorID, role}
 */
async function getUserDirectMonitors(userID) {
    const rows = await R.getAll(
        `SELECT um.monitor_id AS monitorID, um.role, m.name AS monitorName, m.type AS monitorType
         FROM user_monitor um
         JOIN monitor m ON m.id = um.monitor_id
         WHERE um.user_id = ?
         ORDER BY m.name ASC`,
        [userID]
    );
    return rows;
}

/**
 * Assign a monitor directly to a user
 * @param {number} userID ID of user
 * @param {number} monitorID ID of monitor
 * @param {string} role Role (admin or readonly)
 * @returns {Promise<void>}
 */
async function assignMonitorToUser(userID, monitorID, role = MONITOR_ROLES.READONLY) {
    const existing = await R.getRow(
        "SELECT id FROM user_monitor WHERE user_id = ? AND monitor_id = ?",
        [userID, monitorID]
    );
    if (existing) {
        await R.exec(
            "UPDATE user_monitor SET role = ? WHERE user_id = ? AND monitor_id = ?",
            [role, userID, monitorID]
        );
        return;
    }

    let bean = R.dispense("user_monitor");
    bean.user_id = userID;
    bean.monitor_id = monitorID;
    bean.role = role;
    await R.store(bean);
}

/**
 * Remove a direct monitor assignment from a user
 * @param {number} userID ID of user
 * @param {number} monitorID ID of monitor
 * @returns {Promise<void>}
 */
async function unassignMonitorFromUser(userID, monitorID) {
    await R.exec(
        "DELETE FROM user_monitor WHERE user_id = ? AND monitor_id = ?",
        [userID, monitorID]
    );
}

/**
 * Get monitors assigned to a permission group
 * @param {number} groupID Permission group ID
 * @returns {Promise<object[]>} Array of monitor info
 */
async function getGroupMonitors(groupID) {
    const rows = await R.getAll(
        `SELECT id, name, type, parent FROM monitor
         WHERE permission_group_id = ?
         ORDER BY name ASC`,
        [groupID]
    );
    return rows;
}

/**
 * Assign a monitor to a permission group
 * @param {number} monitorID Monitor ID
 * @param {number} groupID Permission group ID
 * @returns {Promise<void>}
 */
async function assignMonitorToGroup(monitorID, groupID) {
    await R.exec(
        "UPDATE monitor SET permission_group_id = ? WHERE id = ?",
        [groupID, monitorID]
    );
}

/**
 * Remove a monitor from its permission group (set to null)
 * @param {number} monitorID Monitor ID
 * @returns {Promise<void>}
 */
async function unassignMonitorFromGroup(monitorID) {
    await R.exec(
        "UPDATE monitor SET permission_group_id = NULL WHERE id = ?",
        [monitorID]
    );
}

/**
 * Assert that the user can edit a monitor, throw if not
 * @param {Socket} socket Socket.io instance
 * @param {number} monitorID ID of monitor
 * @returns {Promise<void>}
 * @throws {Error} Permission denied
 */
async function assertCanEditMonitor(socket, monitorID) {
    checkLogin(socket);
    const allowed = await canEditMonitor(socket.userID, monitorID, socket.userRole);
    if (!allowed) {
        throw new Error("Permission denied. You cannot edit this monitor.");
    }
}

/**
 * Assert that the user can view a monitor, throw if not
 * @param {Socket} socket Socket.io instance
 * @param {number} monitorID ID of monitor
 * @returns {Promise<void>}
 * @throws {Error} Permission denied
 */
async function assertCanAccessMonitor(socket, monitorID) {
    checkLogin(socket);
    const allowed = await canAccessMonitor(socket.userID, monitorID, socket.userRole);
    if (!allowed) {
        throw new Error("Permission denied. You cannot access this monitor.");
    }
}

/**
 * Assert that the user can edit a maintenance, throw if not.
 * Full-admins can always edit. Owner can always edit. Group-admins in the same permission group can edit.
 * @param {Socket} socket Socket.io instance
 * @param {object} maintenance Maintenance bean or object with user_id and permission_group_id
 * @returns {Promise<void>}
 * @throws {Error} Permission denied
 */
async function assertCanEditMaintenance(socket, maintenance) {
    checkLogin(socket);
    if (socket.userRole === ROLES.FULL_ADMIN) {
        return;
    }
    if (maintenance.user_id === socket.userID) {
        return;
    }
    const canEdit = await canEditInGroup(socket.userID, maintenance.permission_group_id, socket.userRole);
    if (!canEdit) {
        throw new Error("Permission denied. You cannot edit this maintenance.");
    }
}

/**
 * Assert that the user can access a maintenance, throw if not.
 * Full-admins can always access. Owner can always access. Members of the same permission group can access.
 * @param {Socket} socket Socket.io instance
 * @param {object} maintenance Maintenance bean or object with user_id and permission_group_id
 * @returns {Promise<void>}
 * @throws {Error} Permission denied
 */
async function assertCanAccessMaintenance(socket, maintenance) {
    checkLogin(socket);
    if (socket.userRole === ROLES.FULL_ADMIN) {
        return;
    }
    if (maintenance.user_id === socket.userID) {
        return;
    }
    const canAccess = await canAccessGroup(socket.userID, maintenance.permission_group_id, socket.userRole);
    if (!canAccess) {
        throw new Error("Permission denied. You cannot access this maintenance.");
    }
}

/**
 * Check if a user can create monitors (requires full-admin or group-admin)
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 * @throws {Error} Permission denied
 */
function checkCanCreateMonitor(socket) {
    checkLogin(socket);
    if (socket.userRole === ROLES.GROUP_READONLY ||
        socket.userRole === ROLES.MONITOR_ADMIN ||
        socket.userRole === ROLES.MONITOR_READONLY) {
        throw new Error("Permission denied. Only full-admins and group-admins can create monitors.");
    }
}

module.exports = {
    ROLES,
    MONITOR_ROLES,
    checkLogin,
    checkFullAdmin,
    getUserRole,
    getUserGroupRole,
    getUserPermissionGroups,
    getAccessibleMonitorIDs,
    canAccessMonitor,
    canEditMonitor,
    canAccessGroup,
    canEditInGroup,
    getUserGroupIDs,
    getUserDirectMonitors,
    assignMonitorToUser,
    unassignMonitorFromUser,
    getGroupMonitors,
    assignMonitorToGroup,
    unassignMonitorFromGroup,
    assertCanEditMonitor,
    assertCanAccessMonitor,
    assertCanEditMaintenance,
    assertCanAccessMaintenance,
    checkCanCreateMonitor,
};
