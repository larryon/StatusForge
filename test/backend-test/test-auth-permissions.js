const { describe, test, before, after } = require("node:test");
const assert = require("node:assert");
const { ROLES } = require("../../server/auth-permissions");

describe("Auth Permissions - ROLES", () => {
    test("ROLES enum has expected values", () => {
        assert.strictEqual(ROLES.ADMIN, "admin");
        assert.strictEqual(ROLES.READ_ONLY, "read-only");
    });

    test("ROLES enum has exactly 2 roles", () => {
        const roleKeys = Object.keys(ROLES);
        assert.strictEqual(roleKeys.length, 2);
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

describe("Auth Permissions - checkAdmin", () => {
    const { checkAdmin } = require("../../server/auth-permissions");

    test("should throw if not logged in", () => {
        assert.throws(() => {
            checkAdmin({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });

    test("should throw if read-only user", () => {
        assert.throws(() => {
            checkAdmin({ userID: 1, userRole: ROLES.READ_ONLY });
        }, {
            message: "Permission denied. Admin access required.",
        });
    });

    test("should not throw if admin", () => {
        assert.doesNotThrow(() => {
            checkAdmin({ userID: 1, userRole: ROLES.ADMIN });
        });
    });
});

describe("Auth Permissions - checkCanCreateMonitor", () => {
    const { checkCanCreateMonitor } = require("../../server/auth-permissions");

    test("should throw if read-only", () => {
        assert.throws(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.READ_ONLY });
        }, {
            message: "Permission denied. Admin access required.",
        });
    });

    test("should not throw if admin", () => {
        assert.doesNotThrow(() => {
            checkCanCreateMonitor({ userID: 1, userRole: ROLES.ADMIN });
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

describe("Auth Permissions - assertCanEditMonitor", () => {
    const { assertCanEditMonitor } = require("../../server/auth-permissions");

    test("admin passes", () => {
        assert.doesNotThrow(() => {
            assertCanEditMonitor({ userID: 1, userRole: ROLES.ADMIN });
        });
    });

    test("read-only throws", () => {
        assert.throws(() => {
            assertCanEditMonitor({ userID: 1, userRole: ROLES.READ_ONLY });
        }, {
            message: "Permission denied. Admin access required.",
        });
    });

    test("not logged in throws", () => {
        assert.throws(() => {
            assertCanEditMonitor({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });
});

describe("Auth Permissions - assertCanAccessMonitor", () => {
    const { assertCanAccessMonitor } = require("../../server/auth-permissions");

    test("admin passes", () => {
        assert.doesNotThrow(() => {
            assertCanAccessMonitor({ userID: 1, userRole: ROLES.ADMIN });
        });
    });

    test("read-only passes (can view all)", () => {
        assert.doesNotThrow(() => {
            assertCanAccessMonitor({ userID: 1, userRole: ROLES.READ_ONLY });
        });
    });

    test("not logged in throws", () => {
        assert.throws(() => {
            assertCanAccessMonitor({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });
});

describe("Auth Permissions - assertCanEditMaintenance", () => {
    const { assertCanEditMaintenance } = require("../../server/auth-permissions");

    test("admin passes", () => {
        assert.doesNotThrow(() => {
            assertCanEditMaintenance({ userID: 1, userRole: ROLES.ADMIN });
        });
    });

    test("read-only throws", () => {
        assert.throws(() => {
            assertCanEditMaintenance({ userID: 1, userRole: ROLES.READ_ONLY });
        }, {
            message: "Permission denied. Admin access required.",
        });
    });

    test("not logged in throws", () => {
        assert.throws(() => {
            assertCanEditMaintenance({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });
});

describe("Auth Permissions - assertCanAccessMaintenance", () => {
    const { assertCanAccessMaintenance } = require("../../server/auth-permissions");

    test("admin passes", () => {
        assert.doesNotThrow(() => {
            assertCanAccessMaintenance({ userID: 1, userRole: ROLES.ADMIN });
        });
    });

    test("read-only passes (can view all)", () => {
        assert.doesNotThrow(() => {
            assertCanAccessMaintenance({ userID: 1, userRole: ROLES.READ_ONLY });
        });
    });

    test("not logged in throws", () => {
        assert.throws(() => {
            assertCanAccessMaintenance({ userID: null });
        }, {
            message: "You are not logged in.",
        });
    });
});

describe("Auth Permissions - getUserRole", () => {
    const TestDB = require("../mock-testdb");
    const { R } = require("redbean-node");
    const { getUserRole } = require("../../server/auth-permissions");

    let testDB;
    let adminUserID;
    let readOnlyUserID;
    let inactiveUserID;

    before(async () => {
        testDB = new TestDB("./data/test-auth-perms-simple");
        await testDB.create();

        const admin = R.dispense("user");
        admin.username = "test_admin";
        admin.password = "hashed_pass";
        admin.role = ROLES.ADMIN;
        admin.active = 1;
        adminUserID = await R.store(admin);

        const readOnlyUser = R.dispense("user");
        readOnlyUser.username = "test_readonly";
        readOnlyUser.password = "hashed_pass";
        readOnlyUser.role = ROLES.READ_ONLY;
        readOnlyUser.active = 1;
        readOnlyUserID = await R.store(readOnlyUser);

        const inactiveUser = R.dispense("user");
        inactiveUser.username = "test_inactive";
        inactiveUser.password = "hashed_pass";
        inactiveUser.role = ROLES.ADMIN;
        inactiveUser.active = 0;
        inactiveUserID = await R.store(inactiveUser);
    });

    after(async () => {
        await testDB.destroy();
    });

    test("returns admin role for active admin user", async () => {
        const role = await getUserRole(adminUserID);
        assert.strictEqual(role, ROLES.ADMIN);
    });

    test("returns read-only role for active read-only user", async () => {
        const role = await getUserRole(readOnlyUserID);
        assert.strictEqual(role, ROLES.READ_ONLY);
    });

    test("throws for non-existent user", async () => {
        await assert.rejects(async () => {
            await getUserRole(999999);
        }, {
            message: "User not found or inactive.",
        });
    });

    test("throws for inactive user", async () => {
        await assert.rejects(async () => {
            await getUserRole(inactiveUserID);
        }, {
            message: "User not found or inactive.",
        });
    });
});

