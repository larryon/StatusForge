const { describe, test, before, after } = require("node:test");
const assert = require("node:assert");
const { ROLES, MONITOR_ROLES } = require("../../server/auth-permissions");

describe("Auth Permissions - ROLES", () => {
    test("ROLES enum has expected values", () => {
        assert.strictEqual(ROLES.FULL_ADMIN, "full-admin");
        assert.strictEqual(ROLES.GROUP_ADMIN, "group-admin");
        assert.strictEqual(ROLES.GROUP_READONLY, "group-readonly");
        assert.strictEqual(ROLES.MONITOR_ADMIN, "monitor-admin");
        assert.strictEqual(ROLES.MONITOR_READONLY, "monitor-read-only");
    });

    test("ROLES enum has exactly 5 roles", () => {
        const roleKeys = Object.keys(ROLES);
        assert.strictEqual(roleKeys.length, 5);
    });
});

describe("Auth Permissions - checkLogin", () => {
    const { checkLogin } = require("../../server/auth-permissions");

    test("should throw if socket has no userID", () => {
        assert.throws(() => {
            checkLogin({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });

    test("should throw if socket userID is undefined", () => {
        assert.throws(() => {
            checkLogin({});
        }, {
            message: "You are not logged in.",
        });
    });

    test("should not throw if socket has userID", () => {
        assert.doesNotThrow(() => {
            checkLogin({ userID: 1 });
        });
    });
});

describe("Auth Permissions - checkFullAdmin", () => {
    const { checkFullAdmin } = require("../../server/auth-permissions");

    test("should throw if not logged in", () => {
        assert.throws(() => {
            checkFullAdmin({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });

    test("should throw if not full-admin", () => {
        assert.throws(() => {
            checkFullAdmin({ userID: 1, userRole: ROLES.GROUP_ADMIN });
        }, {
            message: "Permission denied. Full-Admin access required.",
        });
    });

    test("should throw if group-readonly", () => {
        assert.throws(() => {
            checkFullAdmin({ userID: 1, userRole: ROLES.GROUP_READONLY });
        }, {
            message: "Permission denied. Full-Admin access required.",
        });
    });

    test("should throw if monitor-admin", () => {
        assert.throws(() => {
            checkFullAdmin({ userID: 1, userRole: ROLES.MONITOR_ADMIN });
        }, {
            message: "Permission denied. Full-Admin access required.",
        });
    });

    test("should throw if monitor-read-only", () => {
        assert.throws(() => {
            checkFullAdmin({ userID: 1, userRole: ROLES.MONITOR_READONLY });
        }, {
            message: "Permission denied. Full-Admin access required.",
        });
    });

    test("should not throw if full-admin", () => {
        assert.doesNotThrow(() => {
            checkFullAdmin({ userID: 1, userRole: ROLES.FULL_ADMIN });
        });
    });
});

describe("Auth Permissions - checkCanCreateMonitor", () => {
    const { checkCanCreateMonitor } = require("../../server/auth-permissions");

    test("should throw if group-readonly", () => {
        assert.throws(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.GROUP_READONLY });
        }, {
            message: "Permission denied. Only full-admins and group-admins can create monitors.",
        });
    });

    test("should not throw if full-admin", () => {
        assert.doesNotThrow(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.FULL_ADMIN });
        });
    });

    test("should not throw if group-admin", () => {
        assert.doesNotThrow(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.GROUP_ADMIN });
        });
    });

    test("should throw if monitor-admin", () => {
        assert.throws(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.MONITOR_ADMIN });
        }, {
            message: "Permission denied. Only full-admins and group-admins can create monitors.",
        });
    });

    test("should throw if monitor-read-only", () => {
        assert.throws(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.MONITOR_READONLY });
        }, {
            message: "Permission denied. Only full-admins and group-admins can create monitors.",
        });
    });

    test("should throw if not logged in", () => {
        assert.throws(() => {
            checkCanCreateMonitor({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });
});

describe("Auth Permissions - MONITOR_ROLES", () => {
    const { MONITOR_ROLES } = require("../../server/auth-permissions");

    test("MONITOR_ROLES has expected values", () => {
        assert.strictEqual(MONITOR_ROLES.ADMIN, "admin");
        assert.strictEqual(MONITOR_ROLES.READONLY, "readonly");
    });

    test("MONITOR_ROLES has exactly 2 roles", () => {
        assert.strictEqual(Object.keys(MONITOR_ROLES).length, 2);
    });
});

describe("Auth Permissions - DB functions", () => {
    const TestDB = require("../mock-testdb");
    const { R } = require("redbean-node");
    const {
        canAccessMonitor,
        canEditMonitor,
        getAccessibleMonitorIDs,
        getUserRole,
        getUserGroupRole,
        getUserPermissionGroups,
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
    } = require("../../server/auth-permissions");

    let testDB;
    let adminUserID;
    let groupAdminID;
    let readonlyUserID;
    let monitorAdminID;
    let monitorReadonlyID;
    let inactiveUserID;
    let monitor1ID;
    let monitor2ID;
    let monitor3ID;
    let parentGroupID;
    let childMonitorID;
    let permGroupID;
    let permGroup2ID;

    before(async () => {
        testDB = new TestDB("./data/test-auth-perms-all");
        await testDB.create();

        // --- Users ---
        const admin = R.dispense("user");
        admin.username = "test_admin";
        admin.password = "hashed_pass";
        admin.role = ROLES.FULL_ADMIN;
        admin.active = 1;
        adminUserID = await R.store(admin);

        const groupAdmin = R.dispense("user");
        groupAdmin.username = "test_group_admin";
        groupAdmin.password = "hashed_pass";
        groupAdmin.role = ROLES.GROUP_ADMIN;
        groupAdmin.active = 1;
        groupAdminID = await R.store(groupAdmin);

        const readonlyUser = R.dispense("user");
        readonlyUser.username = "test_readonly";
        readonlyUser.password = "hashed_pass";
        readonlyUser.role = ROLES.GROUP_READONLY;
        readonlyUser.active = 1;
        readonlyUserID = await R.store(readonlyUser);

        const monitorAdmin = R.dispense("user");
        monitorAdmin.username = "test_monitor_admin";
        monitorAdmin.password = "hashed_pass";
        monitorAdmin.role = ROLES.MONITOR_ADMIN;
        monitorAdmin.active = 1;
        monitorAdminID = await R.store(monitorAdmin);

        const monitorReadonly = R.dispense("user");
        monitorReadonly.username = "test_monitor_readonly";
        monitorReadonly.password = "hashed_pass";
        monitorReadonly.role = ROLES.MONITOR_READONLY;
        monitorReadonly.active = 1;
        monitorReadonlyID = await R.store(monitorReadonly);

        const inactiveUser = R.dispense("user");
        inactiveUser.username = "test_inactive";
        inactiveUser.password = "hashed_pass";
        inactiveUser.role = ROLES.GROUP_ADMIN;
        inactiveUser.active = 0;
        inactiveUserID = await R.store(inactiveUser);

        // --- Permission Groups ---
        const pg = R.dispense("permission_group");
        pg.name = "Test Group A";
        pg.active = 1;
        permGroupID = await R.store(pg);

        const pg2 = R.dispense("permission_group");
        pg2.name = "Test Group B";
        pg2.active = 1;
        permGroup2ID = await R.store(pg2);

        // --- Monitors ---
        const m1 = R.dispense("monitor");
        m1.name = "Test Monitor 1";
        m1.type = "http";
        m1.url = "https://example.com";
        m1.interval = 60;
        m1.active = 1;
        m1.user_id = adminUserID;
        monitor1ID = await R.store(m1);

        // Assign monitor1 to group A
        await R.exec("UPDATE monitor SET permission_group_id = ? WHERE id = ?", [permGroupID, monitor1ID]);

        const m2 = R.dispense("monitor");
        m2.name = "Test Monitor 2";
        m2.type = "http";
        m2.url = "https://example2.com";
        m2.interval = 60;
        m2.active = 1;
        m2.user_id = adminUserID;
        monitor2ID = await R.store(m2);

        const m3 = R.dispense("monitor");
        m3.name = "Test Monitor 3 (unassigned)";
        m3.type = "http";
        m3.url = "https://example3.com";
        m3.interval = 60;
        m3.active = 1;
        m3.user_id = adminUserID;
        monitor3ID = await R.store(m3);

        // Group-type parent and child
        const parentGroup = R.dispense("monitor");
        parentGroup.name = "Parent Group";
        parentGroup.type = "group";
        parentGroup.active = 1;
        parentGroup.user_id = adminUserID;
        parentGroupID = await R.store(parentGroup);

        const child = R.dispense("monitor");
        child.name = "Child Monitor";
        child.type = "http";
        child.url = "https://child.example.com";
        child.interval = 60;
        child.active = 1;
        child.parent = parentGroupID;
        child.user_id = adminUserID;
        childMonitorID = await R.store(child);

        // --- User-Permission Group assignments ---
        const upg1 = R.dispense("user_permission_group");
        upg1.user_id = groupAdminID;
        upg1.permission_group_id = permGroupID;
        upg1.role = ROLES.GROUP_ADMIN;
        await R.store(upg1);

        const upg2 = R.dispense("user_permission_group");
        upg2.user_id = readonlyUserID;
        upg2.permission_group_id = permGroupID;
        upg2.role = ROLES.GROUP_READONLY;
        await R.store(upg2);

        // --- Direct user-monitor assignments ---
        const um1 = R.dispense("user_monitor");
        um1.user_id = readonlyUserID;
        um1.monitor_id = monitor2ID;
        um1.role = MONITOR_ROLES.READONLY;
        await R.store(um1);

        const um2 = R.dispense("user_monitor");
        um2.user_id = groupAdminID;
        um2.monitor_id = parentGroupID;
        um2.role = MONITOR_ROLES.ADMIN;
        await R.store(um2);

        const um3 = R.dispense("user_monitor");
        um3.user_id = monitorAdminID;
        um3.monitor_id = monitor2ID;
        um3.role = MONITOR_ROLES.ADMIN;
        await R.store(um3);

        const um4 = R.dispense("user_monitor");
        um4.user_id = monitorReadonlyID;
        um4.monitor_id = monitor2ID;
        um4.role = MONITOR_ROLES.READONLY;
        await R.store(um4);
    });

    after(async () => {
        await testDB.destroy();
    });

    // ===================== getUserRole =====================

    test("getUserRole: returns role for active user", async () => {
        const role = await getUserRole(adminUserID);
        assert.strictEqual(role, ROLES.FULL_ADMIN);
    });

    test("getUserRole: returns group-admin role", async () => {
        const role = await getUserRole(groupAdminID);
        assert.strictEqual(role, ROLES.GROUP_ADMIN);
    });

    test("getUserRole: throws for non-existent user", async () => {
        await assert.rejects(async () => {
            await getUserRole(999999);
        }, {
            message: "User not found or inactive.",
        });
    });

    test("getUserRole: throws for inactive user", async () => {
        await assert.rejects(async () => {
            await getUserRole(inactiveUserID);
        }, {
            message: "User not found or inactive.",
        });
    });

    // ===================== getUserGroupRole =====================

    test("getUserGroupRole: returns role for user in group", async () => {
        const role = await getUserGroupRole(groupAdminID, permGroupID);
        assert.strictEqual(role, ROLES.GROUP_ADMIN);
    });

    test("getUserGroupRole: returns null for user NOT in group", async () => {
        const role = await getUserGroupRole(adminUserID, permGroupID);
        assert.strictEqual(role, null);
    });

    test("getUserGroupRole: returns null for non-existent group", async () => {
        const role = await getUserGroupRole(groupAdminID, 999999);
        assert.strictEqual(role, null);
    });

    test("getUserGroupRole: returns readonly role", async () => {
        const role = await getUserGroupRole(readonlyUserID, permGroupID);
        assert.strictEqual(role, ROLES.GROUP_READONLY);
    });

    // ===================== getUserPermissionGroups =====================

    test("getUserPermissionGroups: returns groups for group-admin", async () => {
        const groups = await getUserPermissionGroups(groupAdminID);
        assert.ok(Array.isArray(groups));
        assert.ok(groups.length >= 1);
        const found = groups.find(g => g.groupId === permGroupID);
        assert.ok(found);
        assert.strictEqual(found.groupName, "Test Group A");
        assert.strictEqual(found.role, ROLES.GROUP_ADMIN);
    });

    test("getUserPermissionGroups: returns empty for user with no groups", async () => {
        const groups = await getUserPermissionGroups(adminUserID);
        assert.ok(Array.isArray(groups));
        assert.strictEqual(groups.length, 0);
    });

    // ===================== getUserGroupIDs =====================

    test("getUserGroupIDs: returns group IDs for member", async () => {
        const ids = await getUserGroupIDs(groupAdminID);
        assert.ok(Array.isArray(ids));
        assert.ok(ids.includes(permGroupID));
    });

    test("getUserGroupIDs: returns empty for user with no groups", async () => {
        const ids = await getUserGroupIDs(adminUserID);
        assert.ok(Array.isArray(ids));
        assert.strictEqual(ids.length, 0);
    });

    // ===================== canAccessGroup =====================

    test("canAccessGroup: full-admin can access any group", async () => {
        const result = await canAccessGroup(adminUserID, permGroupID, ROLES.FULL_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessGroup: member can access their group", async () => {
        const result = await canAccessGroup(groupAdminID, permGroupID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessGroup: readonly member can access their group", async () => {
        const result = await canAccessGroup(readonlyUserID, permGroupID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, true);
    });

    test("canAccessGroup: outsider cannot access", async () => {
        const result = await canAccessGroup(monitorAdminID, permGroupID, ROLES.MONITOR_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canAccessGroup: returns false for null permissionGroupId", async () => {
        const result = await canAccessGroup(groupAdminID, null, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canAccessGroup: returns false for undefined permissionGroupId", async () => {
        const result = await canAccessGroup(groupAdminID, undefined, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, false);
    });

    // ===================== canEditInGroup =====================

    test("canEditInGroup: full-admin can edit in any group", async () => {
        const result = await canEditInGroup(adminUserID, permGroupID, ROLES.FULL_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditInGroup: group-admin member can edit", async () => {
        const result = await canEditInGroup(groupAdminID, permGroupID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditInGroup: readonly member cannot edit", async () => {
        const result = await canEditInGroup(readonlyUserID, permGroupID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, false);
    });

    test("canEditInGroup: returns false for null permissionGroupId", async () => {
        const result = await canEditInGroup(groupAdminID, null, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canEditInGroup: outsider cannot edit", async () => {
        const result = await canEditInGroup(monitorAdminID, permGroupID, ROLES.MONITOR_ADMIN);
        assert.strictEqual(result, false);
    });

    // ===================== canAccessMonitor =====================

    test("canAccessMonitor: full-admin can access any monitor", async () => {
        const result = await canAccessMonitor(adminUserID, monitor1ID, ROLES.FULL_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: full-admin can access unassigned monitor", async () => {
        const result = await canAccessMonitor(adminUserID, 999999, ROLES.FULL_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: group-admin via permission group", async () => {
        const result = await canAccessMonitor(groupAdminID, monitor1ID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: group-admin cannot access unrelated monitor", async () => {
        const result = await canAccessMonitor(groupAdminID, monitor2ID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canAccessMonitor: readonly user via direct assignment", async () => {
        const result = await canAccessMonitor(readonlyUserID, monitor2ID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: readonly user cannot access unassigned", async () => {
        const result = await canAccessMonitor(readonlyUserID, monitor3ID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, false);
    });

    test("canAccessMonitor: readonly user via permission group", async () => {
        const result = await canAccessMonitor(readonlyUserID, monitor1ID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: parent inheritance — child of assigned parent", async () => {
        const result = await canAccessMonitor(groupAdminID, childMonitorID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: monitor-admin via direct assignment", async () => {
        const result = await canAccessMonitor(monitorAdminID, monitor2ID, ROLES.MONITOR_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: monitor-admin cannot access unassigned", async () => {
        const result = await canAccessMonitor(monitorAdminID, monitor1ID, ROLES.MONITOR_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canAccessMonitor: monitor-readonly via direct assignment", async () => {
        const result = await canAccessMonitor(monitorReadonlyID, monitor2ID, ROLES.MONITOR_READONLY);
        assert.strictEqual(result, true);
    });

    test("canAccessMonitor: depth limit prevents infinite recursion", async () => {
        const result = await canAccessMonitor(readonlyUserID, 999998, ROLES.GROUP_READONLY);
        assert.strictEqual(result, false);
    });

    // ===================== canEditMonitor =====================

    test("canEditMonitor: full-admin can edit any monitor", async () => {
        const result = await canEditMonitor(adminUserID, monitor1ID, ROLES.FULL_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditMonitor: readonly user cannot edit even assigned", async () => {
        const result = await canEditMonitor(readonlyUserID, monitor2ID, ROLES.GROUP_READONLY);
        assert.strictEqual(result, false);
    });

    test("canEditMonitor: group-admin can edit in their permission group", async () => {
        const result = await canEditMonitor(groupAdminID, monitor1ID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditMonitor: group-admin cannot edit unrelated monitor", async () => {
        const result = await canEditMonitor(groupAdminID, monitor2ID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, false);
    });

    test("canEditMonitor: group-admin via direct admin assignment", async () => {
        const result = await canEditMonitor(groupAdminID, parentGroupID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditMonitor: parent inheritance — edit child via assigned parent", async () => {
        const result = await canEditMonitor(groupAdminID, childMonitorID, ROLES.GROUP_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditMonitor: monitor-admin can edit directly assigned", async () => {
        const result = await canEditMonitor(monitorAdminID, monitor2ID, ROLES.MONITOR_ADMIN);
        assert.strictEqual(result, true);
    });

    test("canEditMonitor: monitor-readonly cannot edit even assigned", async () => {
        const result = await canEditMonitor(monitorReadonlyID, monitor2ID, ROLES.MONITOR_READONLY);
        assert.strictEqual(result, false);
    });

    // ===================== getAccessibleMonitorIDs =====================

    test("getAccessibleMonitorIDs: group-admin includes group + direct", async () => {
        const ids = await getAccessibleMonitorIDs(groupAdminID);
        assert.ok(ids instanceof Set);
        assert.ok(ids.has(monitor1ID), "Should include permission-group monitor");
        assert.ok(ids.has(parentGroupID), "Should include directly-assigned parent");
        assert.ok(ids.has(childMonitorID), "Should include child via parent inheritance");
        assert.ok(!ids.has(monitor2ID), "Should NOT include unrelated monitor");
    });

    test("getAccessibleMonitorIDs: readonly user includes directly-assigned", async () => {
        const ids = await getAccessibleMonitorIDs(readonlyUserID);
        assert.ok(ids.has(monitor2ID), "Should include directly-assigned monitor");
    });

    test("getAccessibleMonitorIDs: monitor-admin gets flat list (no parent walk-up)", async () => {
        const ids = await getAccessibleMonitorIDs(monitorAdminID, ROLES.MONITOR_ADMIN);
        assert.ok(ids instanceof Set);
        assert.ok(ids.has(monitor2ID));
    });

    test("getAccessibleMonitorIDs: monitor-readonly gets flat list", async () => {
        const ids = await getAccessibleMonitorIDs(monitorReadonlyID, ROLES.MONITOR_READONLY);
        assert.ok(ids instanceof Set);
        assert.ok(ids.has(monitor2ID));
    });

    // ===================== getUserDirectMonitors =====================

    test("getUserDirectMonitors: returns assigned monitors", async () => {
        const monitors = await getUserDirectMonitors(readonlyUserID);
        assert.ok(Array.isArray(monitors));
        assert.ok(monitors.length >= 1);
        const found = monitors.find(m => m.monitorID === monitor2ID);
        assert.ok(found);
        assert.strictEqual(found.role, MONITOR_ROLES.READONLY);
        assert.strictEqual(found.monitorName, "Test Monitor 2");
        assert.strictEqual(found.monitorType, "http");
    });

    test("getUserDirectMonitors: returns empty for user with none", async () => {
        const monitors = await getUserDirectMonitors(adminUserID);
        assert.ok(Array.isArray(monitors));
        assert.strictEqual(monitors.length, 0);
    });

    // ===================== assignMonitorToUser / unassignMonitorFromUser =====================

    test("assignMonitorToUser: creates new assignment with default readonly role", async () => {
        await assignMonitorToUser(adminUserID, monitor3ID);
        const monitors = await getUserDirectMonitors(adminUserID);
        const found = monitors.find(m => m.monitorID === monitor3ID);
        assert.ok(found);
        assert.strictEqual(found.role, MONITOR_ROLES.READONLY);
    });

    test("assignMonitorToUser: updates role on re-assignment", async () => {
        await assignMonitorToUser(adminUserID, monitor3ID, MONITOR_ROLES.ADMIN);
        const monitors = await getUserDirectMonitors(adminUserID);
        const found = monitors.find(m => m.monitorID === monitor3ID);
        assert.ok(found);
        assert.strictEqual(found.role, MONITOR_ROLES.ADMIN);
    });

    test("unassignMonitorFromUser: removes assignment", async () => {
        await unassignMonitorFromUser(adminUserID, monitor3ID);
        const monitors = await getUserDirectMonitors(adminUserID);
        const found = monitors.find(m => m.monitorID === monitor3ID);
        assert.strictEqual(found, undefined);
    });

    test("unassignMonitorFromUser: does not throw for non-existent assignment", async () => {
        await assert.doesNotReject(async () => {
            await unassignMonitorFromUser(adminUserID, 999999);
        });
    });

    // ===================== getGroupMonitors / assignMonitorToGroup / unassignMonitorFromGroup =====================

    test("getGroupMonitors: returns monitors in group", async () => {
        const monitors = await getGroupMonitors(permGroupID);
        assert.ok(Array.isArray(monitors));
        const found = monitors.find(m => m.id === monitor1ID);
        assert.ok(found);
        assert.strictEqual(found.name, "Test Monitor 1");
    });

    test("getGroupMonitors: returns empty for group with no monitors", async () => {
        const monitors = await getGroupMonitors(permGroup2ID);
        assert.ok(Array.isArray(monitors));
        assert.strictEqual(monitors.length, 0);
    });

    test("assignMonitorToGroup: sets group on monitor", async () => {
        await assignMonitorToGroup(monitor3ID, permGroup2ID);
        const monitors = await getGroupMonitors(permGroup2ID);
        const found = monitors.find(m => m.id === monitor3ID);
        assert.ok(found);
    });

    test("unassignMonitorFromGroup: removes group from monitor", async () => {
        await unassignMonitorFromGroup(monitor3ID);
        const monitors = await getGroupMonitors(permGroup2ID);
        const found = monitors.find(m => m.id === monitor3ID);
        assert.strictEqual(found, undefined);
    });

    // ===================== assertCanEditMonitor =====================

    test("assertCanEditMonitor: full-admin passes", async () => {
        await assert.doesNotReject(async () => {
            await assertCanEditMonitor({ userID: adminUserID, userRole: ROLES.FULL_ADMIN }, monitor1ID);
        });
    });

    test("assertCanEditMonitor: group-admin in group passes", async () => {
        await assert.doesNotReject(async () => {
            await assertCanEditMonitor({ userID: groupAdminID, userRole: ROLES.GROUP_ADMIN }, monitor1ID);
        });
    });

    test("assertCanEditMonitor: readonly throws even if group member", async () => {
        await assert.rejects(async () => {
            await assertCanEditMonitor({ userID: readonlyUserID, userRole: ROLES.GROUP_READONLY }, monitor1ID);
        }, {
            message: "Permission denied. You cannot edit this monitor.",
        });
    });

    test("assertCanEditMonitor: not logged in throws", async () => {
        await assert.rejects(async () => {
            await assertCanEditMonitor({ userID: null }, monitor1ID);
        }, {
            message: "You are not logged in.",
        });
    });

    // ===================== assertCanAccessMonitor =====================

    test("assertCanAccessMonitor: full-admin passes", async () => {
        await assert.doesNotReject(async () => {
            await assertCanAccessMonitor({ userID: adminUserID, userRole: ROLES.FULL_ADMIN }, monitor1ID);
        });
    });

    test("assertCanAccessMonitor: group member passes", async () => {
        await assert.doesNotReject(async () => {
            await assertCanAccessMonitor({ userID: readonlyUserID, userRole: ROLES.GROUP_READONLY }, monitor1ID);
        });
    });

    test("assertCanAccessMonitor: outsider throws", async () => {
        await assert.rejects(async () => {
            await assertCanAccessMonitor({ userID: monitorAdminID, userRole: ROLES.MONITOR_ADMIN }, monitor1ID);
        }, {
            message: "Permission denied. You cannot access this monitor.",
        });
    });

    test("assertCanAccessMonitor: not logged in throws", async () => {
        await assert.rejects(async () => {
            await assertCanAccessMonitor({ userID: null }, monitor1ID);
        }, {
            message: "You are not logged in.",
        });
    });

    // ===================== assertCanEditMaintenance =====================

    test("assertCanEditMaintenance: full-admin passes", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanEditMaintenance({ userID: adminUserID, userRole: ROLES.FULL_ADMIN }, maint);
        });
    });

    test("assertCanEditMaintenance: owner passes", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanEditMaintenance({ userID: groupAdminID, userRole: ROLES.GROUP_ADMIN }, maint);
        });
    });

    test("assertCanEditMaintenance: group-admin in same group passes", async () => {
        const maint = { user_id: adminUserID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanEditMaintenance({ userID: groupAdminID, userRole: ROLES.GROUP_ADMIN }, maint);
        });
    });

    test("assertCanEditMaintenance: readonly member throws", async () => {
        const maint = { user_id: adminUserID, permission_group_id: permGroupID };
        await assert.rejects(async () => {
            await assertCanEditMaintenance({ userID: readonlyUserID, userRole: ROLES.GROUP_READONLY }, maint);
        }, {
            message: "Permission denied. You cannot edit this maintenance.",
        });
    });

    test("assertCanEditMaintenance: outsider throws", async () => {
        const maint = { user_id: adminUserID, permission_group_id: permGroupID };
        await assert.rejects(async () => {
            await assertCanEditMaintenance({ userID: monitorAdminID, userRole: ROLES.MONITOR_ADMIN }, maint);
        }, {
            message: "Permission denied. You cannot edit this maintenance.",
        });
    });

    test("assertCanEditMaintenance: not logged in throws", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.rejects(async () => {
            await assertCanEditMaintenance({ userID: null }, maint);
        }, {
            message: "You are not logged in.",
        });
    });

    // ===================== assertCanAccessMaintenance =====================

    test("assertCanAccessMaintenance: full-admin passes", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanAccessMaintenance({ userID: adminUserID, userRole: ROLES.FULL_ADMIN }, maint);
        });
    });

    test("assertCanAccessMaintenance: owner passes", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanAccessMaintenance({ userID: groupAdminID, userRole: ROLES.GROUP_ADMIN }, maint);
        });
    });

    test("assertCanAccessMaintenance: group member passes", async () => {
        const maint = { user_id: adminUserID, permission_group_id: permGroupID };
        await assert.doesNotReject(async () => {
            await assertCanAccessMaintenance({ userID: readonlyUserID, userRole: ROLES.GROUP_READONLY }, maint);
        });
    });

    test("assertCanAccessMaintenance: outsider throws", async () => {
        const maint = { user_id: adminUserID, permission_group_id: permGroupID };
        await assert.rejects(async () => {
            await assertCanAccessMaintenance({ userID: monitorAdminID, userRole: ROLES.MONITOR_ADMIN }, maint);
        }, {
            message: "Permission denied. You cannot access this maintenance.",
        });
    });

    test("assertCanAccessMaintenance: not logged in throws", async () => {
        const maint = { user_id: groupAdminID, permission_group_id: permGroupID };
        await assert.rejects(async () => {
            await assertCanAccessMaintenance({ userID: null }, maint);
        }, {
            message: "You are not logged in.",
        });
    });

    test("assertCanAccessMaintenance: null permission_group_id — non-owner denied", async () => {
        const maint = { user_id: adminUserID, permission_group_id: null };
        await assert.rejects(async () => {
            await assertCanAccessMaintenance({ userID: groupAdminID, userRole: ROLES.GROUP_ADMIN }, maint);
        }, {
            message: "Permission denied. You cannot access this maintenance.",
        });
    });
});