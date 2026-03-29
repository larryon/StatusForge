const { describe, test, before, after } = require("node:test");
const assert = require("node:assert");

// ---------- Pure unit tests (no DB) ----------

describe("API Auth - API_SCOPES", () => {
    const { API_SCOPES } = require("../../server/modules/api-auth");

    test("has all 19 expected scopes", () => {
        const values = Object.values(API_SCOPES);
        assert.strictEqual(values.length, 19);
    });

    test("scopes follow resource:action format", () => {
        for (const [key, value] of Object.entries(API_SCOPES)) {
            assert.match(value, /^[a-z-]+:[a-z]+$/, `Scope ${key} should match resource:action format`);
        }
    });

    test("includes monitor scopes", () => {
        assert.strictEqual(API_SCOPES.MONITORS_READ, "monitors:read");
        assert.strictEqual(API_SCOPES.MONITORS_WRITE, "monitors:write");
    });

    test("includes notification scopes", () => {
        assert.strictEqual(API_SCOPES.NOTIFICATIONS_READ, "notifications:read");
        assert.strictEqual(API_SCOPES.NOTIFICATIONS_WRITE, "notifications:write");
    });

    test("includes status page scopes", () => {
        assert.strictEqual(API_SCOPES.STATUS_PAGES_READ, "status-pages:read");
        assert.strictEqual(API_SCOPES.STATUS_PAGES_WRITE, "status-pages:write");
    });

    test("includes maintenance scopes", () => {
        assert.strictEqual(API_SCOPES.MAINTENANCE_READ, "maintenance:read");
        assert.strictEqual(API_SCOPES.MAINTENANCE_WRITE, "maintenance:write");
    });

    test("includes tag scopes", () => {
        assert.strictEqual(API_SCOPES.TAGS_READ, "tags:read");
        assert.strictEqual(API_SCOPES.TAGS_WRITE, "tags:write");
    });

    test("includes user scopes", () => {
        assert.strictEqual(API_SCOPES.USERS_READ, "users:read");
        assert.strictEqual(API_SCOPES.USERS_WRITE, "users:write");
    });

    test("includes API key scopes", () => {
        assert.strictEqual(API_SCOPES.API_KEYS_READ, "api-keys:read");
        assert.strictEqual(API_SCOPES.API_KEYS_WRITE, "api-keys:write");
    });

    test("includes uptime scope", () => {
        assert.strictEqual(API_SCOPES.UPTIME_READ, "uptime:read");
    });

    test("includes docker scopes", () => {
        assert.strictEqual(API_SCOPES.DOCKER_READ, "docker:read");
        assert.strictEqual(API_SCOPES.DOCKER_WRITE, "docker:write");
    });

    test("includes settings scopes", () => {
        assert.strictEqual(API_SCOPES.SETTINGS_READ, "settings:read");
        assert.strictEqual(API_SCOPES.SETTINGS_WRITE, "settings:write");
    });
});

describe("API Auth - SCOPE_GROUPS", () => {
    const { SCOPE_GROUPS, API_SCOPES } = require("../../server/modules/api-auth");

    test("has 3 scope groups", () => {
        assert.strictEqual(Object.keys(SCOPE_GROUPS).length, 3);
    });

    test("read-only group has only read scopes", () => {
        const readOnly = SCOPE_GROUPS["read-only"];
        assert.ok(Array.isArray(readOnly));
        for (const scope of readOnly) {
            assert.match(scope, /:read$/, `read-only scope "${scope}" should end with :read`);
        }
    });

    test("read-only group includes monitors:read", () => {
        assert.ok(SCOPE_GROUPS["read-only"].includes(API_SCOPES.MONITORS_READ));
    });

    test("read-only group does NOT include admin scopes", () => {
        assert.ok(!SCOPE_GROUPS["read-only"].includes(API_SCOPES.USERS_READ));
        assert.ok(!SCOPE_GROUPS["read-only"].includes(API_SCOPES.SETTINGS_READ));
    });

    test("read-write group has read AND write scopes", () => {
        const rw = SCOPE_GROUPS["read-write"];
        assert.ok(rw.includes(API_SCOPES.MONITORS_READ));
        assert.ok(rw.includes(API_SCOPES.MONITORS_WRITE));
    });

    test("read-write group does NOT include admin scopes", () => {
        assert.ok(!SCOPE_GROUPS["read-write"].includes(API_SCOPES.USERS_READ));
        assert.ok(!SCOPE_GROUPS["read-write"].includes(API_SCOPES.SETTINGS_WRITE));
    });

    test("full-access group includes ALL scopes", () => {
        const all = SCOPE_GROUPS["full-access"];
        const allScopes = Object.values(API_SCOPES);
        for (const scope of allScopes) {
            assert.ok(all.includes(scope), `full-access should include ${scope}`);
        }
    });

    test("full-access group length matches API_SCOPES count", () => {
        assert.strictEqual(SCOPE_GROUPS["full-access"].length, Object.values(API_SCOPES).length);
    });
});

describe("API Auth - ADMIN_ONLY_SCOPES", () => {
    const { ADMIN_ONLY_SCOPES, API_SCOPES } = require("../../server/modules/api-auth");

    test("is a Set", () => {
        assert.ok(ADMIN_ONLY_SCOPES instanceof Set);
    });

    test("has exactly 4 admin-only scopes", () => {
        assert.strictEqual(ADMIN_ONLY_SCOPES.size, 4);
    });

    test("includes users:read and users:write", () => {
        assert.ok(ADMIN_ONLY_SCOPES.has(API_SCOPES.USERS_READ));
        assert.ok(ADMIN_ONLY_SCOPES.has(API_SCOPES.USERS_WRITE));
    });

    test("includes settings:read and settings:write", () => {
        assert.ok(ADMIN_ONLY_SCOPES.has(API_SCOPES.SETTINGS_READ));
        assert.ok(ADMIN_ONLY_SCOPES.has(API_SCOPES.SETTINGS_WRITE));
    });

    test("does NOT include monitors:read", () => {
        assert.ok(!ADMIN_ONLY_SCOPES.has(API_SCOPES.MONITORS_READ));
    });
});

describe("API Auth - getScopesForRole", () => {
    const { getScopesForRole, SCOPE_GROUPS, API_SCOPES } = require("../../server/modules/api-auth");

    test("admin gets full-access scopes", () => {
        const scopes = getScopesForRole("admin");
        assert.deepStrictEqual(scopes, SCOPE_GROUPS["full-access"]);
    });

    test("read-only gets read-only scopes", () => {
        const scopes = getScopesForRole("read-only");
        assert.deepStrictEqual(scopes, SCOPE_GROUPS["read-only"]);
    });

    test("unknown role defaults to read-only scopes", () => {
        const scopes = getScopesForRole("nonexistent-role");
        assert.deepStrictEqual(scopes, SCOPE_GROUPS["read-only"]);
    });

    test("returns a new array each time (not a reference)", () => {
        const a = getScopesForRole("admin");
        const b = getScopesForRole("admin");
        assert.notStrictEqual(a, b);
        assert.deepStrictEqual(a, b);
    });

    test("admin scopes include admin-only scopes", () => {
        const scopes = getScopesForRole("admin");
        assert.ok(scopes.includes(API_SCOPES.USERS_READ));
        assert.ok(scopes.includes(API_SCOPES.SETTINGS_WRITE));
    });

    test("read-only scopes do NOT include admin-only scopes", () => {
        const scopes = getScopesForRole("read-only");
        assert.ok(!scopes.includes(API_SCOPES.USERS_READ));
        assert.ok(!scopes.includes(API_SCOPES.SETTINGS_WRITE));
    });
});

describe("API Auth - requireScope middleware", () => {
    const { requireScope, API_SCOPES } = require("../../server/modules/api-auth");

    /**
     * Create a mock response object
     * @returns {object} Mock response with status tracking
     */
    function mockRes() {
        const r = {
            statusCode: null,
            body: null,
            /**
             * Set HTTP status code
             * @param {number} code Status code
             * @returns {object} Chainable response
             */
            status(code) {
                r.statusCode = code;
                return r;
            },
            /**
             * Send JSON response body
             * @param {object} obj JSON body
             */
            json(obj) {
                r.body = obj;
            },
        };
        return r;
    }

    test("calls next() when scope is present", () => {
        const req = { apiScopes: new Set(["monitors:read"]) };
        const res = mockRes();
        let nextCalled = false;
        requireScope(API_SCOPES.MONITORS_READ)(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, true);
    });

    test("returns 403 when scope is missing", () => {
        const req = { apiScopes: new Set(["tags:read"]) };
        const res = mockRes();
        let nextCalled = false;
        requireScope(API_SCOPES.MONITORS_READ)(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
        assert.strictEqual(res.body.ok, false);
        assert.ok(res.body.msg.includes("monitors:read"));
    });

    test("returns 403 when apiScopes is undefined", () => {
        const req = {};
        const res = mockRes();
        let nextCalled = false;
        requireScope(API_SCOPES.MONITORS_WRITE)(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
    });

    test("returns 403 when apiScopes is null", () => {
        const req = { apiScopes: null };
        const res = mockRes();
        let nextCalled = false;
        requireScope(API_SCOPES.MONITORS_WRITE)(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
    });

    test("checks exact scope — write does not satisfy read", () => {
        const req = { apiScopes: new Set(["monitors:write"]) };
        const res = mockRes();
        let nextCalled = false;
        requireScope(API_SCOPES.MONITORS_READ)(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
    });
});

describe("API Auth - requireAdmin middleware", () => {
    const { requireAdmin } = require("../../server/modules/api-auth");

    /**
     * Create a mock response object
     * @returns {object} Mock response with status tracking
     */
    function mockRes() {
        const r = {
            statusCode: null,
            body: null,
            /**
             * Set HTTP status code
             * @param {number} code Status code
             * @returns {object} Chainable response
             */
            status(code) {
                r.statusCode = code;
                return r;
            },
            /**
             * Send JSON response body
             * @param {object} obj JSON body
             */
            json(obj) {
                r.body = obj;
            },
        };
        return r;
    }

    test("calls next() for admin user", () => {
        const req = { apiUser: { id: 1 }, userRole: "admin" };
        const res = mockRes();
        let nextCalled = false;
        requireAdmin(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, true);
    });

    test("returns 403 for read-only", () => {
        const req = { apiUser: { id: 1 }, userRole: "read-only" };
        const res = mockRes();
        let nextCalled = false;
        requireAdmin(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
        assert.strictEqual(res.body.ok, false);
    });

    test("returns 403 for unknown role", () => {
        const req = { apiUser: { id: 1 }, userRole: "unknown" };
        const res = mockRes();
        let nextCalled = false;
        requireAdmin(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
    });

    test("returns 403 when apiUser is null", () => {
        const req = { apiUser: null, userRole: "admin" };
        const res = mockRes();
        let nextCalled = false;
        requireAdmin(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
    });

    test("returns 403 when apiUser is missing", () => {
        const req = {};
        const res = mockRes();
        let nextCalled = false;
        requireAdmin(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 403);
    });
});

describe("API Auth - resolveAPIKey (with DB)", () => {
    const TestDB = require("../mock-testdb");
    const { R } = require("redbean-node");
    const passwordHash = require("../../server/password-hash");
    const { resolveAPIKey, API_SCOPES } = require("../../server/modules/api-auth");

    let testDB;
    let adminUserID;
    let readOnlyUserID;
    let clearKey;
    let apiKeyID;
    let expiredKeyID;
    let inactiveKeyID;
    let customScopesKeyID;
    let clearKeyExpired;
    let clearKeyInactive;
    let clearKeyCustom;
    let noPermsKeyID;
    let clearKeyNoPerms;

    before(async () => {
        testDB = new TestDB("./data/test-api-auth");
        await testDB.create();

        // Create an admin user
        const admin = R.dispense("user");
        admin.username = "api_test_admin";
        admin.password = "hashed_pass";
        admin.role = "admin";
        admin.active = 1;
        adminUserID = await R.store(admin);

        // Create a read-only user
        const readOnlyUser = R.dispense("user");
        readOnlyUser.username = "api_test_read_only";
        readOnlyUser.password = "hashed_pass";
        readOnlyUser.role = "read-only";
        readOnlyUser.active = 1;
        readOnlyUserID = await R.store(readOnlyUser);

        // Create a valid API key
        clearKey = "test_clear_key_abc123";
        const hashedKey = await passwordHash.generate(clearKey);
        const key1 = R.dispense("api_key");
        key1.name = "Test Key";
        key1.key = hashedKey;
        key1.user_id = adminUserID;
        key1.active = 1;
        key1.permissions = JSON.stringify([API_SCOPES.MONITORS_READ, API_SCOPES.MONITORS_WRITE]);
        key1.expires = null;
        key1.created_date = new Date().toISOString();
        apiKeyID = await R.store(key1);

        // Create an expired API key
        clearKeyExpired = "test_expired_key_xyz";
        const hashedKeyExpired = await passwordHash.generate(clearKeyExpired);
        const key2 = R.dispense("api_key");
        key2.name = "Expired Key";
        key2.key = hashedKeyExpired;
        key2.user_id = adminUserID;
        key2.active = 1;
        key2.permissions = JSON.stringify([API_SCOPES.MONITORS_READ]);
        key2.expires = "2020-01-01T00:00:00Z";
        key2.created_date = new Date().toISOString();
        expiredKeyID = await R.store(key2);

        // Create an inactive API key
        clearKeyInactive = "test_inactive_key_abc";
        const hashedKeyInactive = await passwordHash.generate(clearKeyInactive);
        const key3 = R.dispense("api_key");
        key3.name = "Inactive Key";
        key3.key = hashedKeyInactive;
        key3.user_id = adminUserID;
        key3.active = 0;
        key3.permissions = JSON.stringify([API_SCOPES.MONITORS_READ]);
        key3.expires = null;
        key3.created_date = new Date().toISOString();
        inactiveKeyID = await R.store(key3);

        // Create an API key with custom scopes (including admin-only) for read-only user
        clearKeyCustom = "test_custom_scope_key";
        const hashedKeyCustom = await passwordHash.generate(clearKeyCustom);
        const key4 = R.dispense("api_key");
        key4.name = "Custom Scopes Key";
        key4.key = hashedKeyCustom;
        key4.user_id = readOnlyUserID;
        key4.active = 1;
        key4.permissions = JSON.stringify([API_SCOPES.MONITORS_READ, API_SCOPES.USERS_READ, API_SCOPES.SETTINGS_WRITE]);
        key4.expires = null;
        key4.created_date = new Date().toISOString();
        customScopesKeyID = await R.store(key4);

        // Create an API key with no permissions field (null) — should inherit from role
        clearKeyNoPerms = "test_no_perms_key";
        const hashedKeyNoPerms = await passwordHash.generate(clearKeyNoPerms);
        const key5 = R.dispense("api_key");
        key5.name = "No Perms Key";
        key5.key = hashedKeyNoPerms;
        key5.user_id = adminUserID;
        key5.active = 1;
        key5.permissions = null;
        key5.expires = null;
        key5.created_date = new Date().toISOString();
        noPermsKeyID = await R.store(key5);
    });

    after(async () => {
        await testDB.destroy();
    });

    test("returns null for non-string input", async () => {
        const result = await resolveAPIKey(123);
        assert.strictEqual(result, null);
    });

    test("returns null for null input", async () => {
        const result = await resolveAPIKey(null);
        assert.strictEqual(result, null);
    });

    test("returns null for string not starting with uk", async () => {
        const result = await resolveAPIKey("Bearer abc123");
        assert.strictEqual(result, null);
    });

    test("returns null for key without underscore", async () => {
        const result = await resolveAPIKey("uk123nounderscore");
        assert.strictEqual(result, null);
    });

    test("returns null for non-existent key ID", async () => {
        const result = await resolveAPIKey("uk99999_somekey");
        assert.strictEqual(result, null);
    });

    test("returns null for expired key", async () => {
        const result = await resolveAPIKey(`uk${expiredKeyID}_${clearKeyExpired}`);
        assert.strictEqual(result, null);
    });

    test("returns null for inactive key", async () => {
        const result = await resolveAPIKey(`uk${inactiveKeyID}_${clearKeyInactive}`);
        assert.strictEqual(result, null);
    });

    test("returns null for wrong clear key", async () => {
        const result = await resolveAPIKey(`uk${apiKeyID}_wrongclearkey`);
        assert.strictEqual(result, null);
    });

    test("returns user and scopes for valid key", async () => {
        const result = await resolveAPIKey(`uk${apiKeyID}_${clearKey}`);
        assert.ok(result);
        assert.strictEqual(result.user.id, adminUserID);
        assert.ok(Array.isArray(result.scopes));
        assert.ok(result.scopes.includes(API_SCOPES.MONITORS_READ));
        assert.ok(result.scopes.includes(API_SCOPES.MONITORS_WRITE));
    });

    test("valid key returns apiKey bean", async () => {
        const result = await resolveAPIKey(`uk${apiKeyID}_${clearKey}`);
        assert.ok(result.apiKey);
        assert.strictEqual(result.apiKey.id, apiKeyID);
    });

    test("admin-only scopes are filtered for non-admin user", async () => {
        const result = await resolveAPIKey(`uk${customScopesKeyID}_${clearKeyCustom}`);
        assert.ok(result);
        assert.strictEqual(result.user.role, "read-only");
        // admin-only scopes should be stripped
        assert.ok(result.scopes.includes(API_SCOPES.MONITORS_READ), "Should keep monitors:read");
        assert.ok(!result.scopes.includes(API_SCOPES.USERS_READ), "Should strip users:read");
        assert.ok(!result.scopes.includes(API_SCOPES.SETTINGS_WRITE), "Should strip settings:write");
    });

    test("null permissions inherits from role", async () => {
        const result = await resolveAPIKey(`uk${noPermsKeyID}_${clearKeyNoPerms}`);
        assert.ok(result);
        // Admin user with null permissions should get full-access scopes
        assert.ok(result.scopes.length > 0);
        assert.ok(result.scopes.includes(API_SCOPES.MONITORS_READ));
        assert.ok(result.scopes.includes(API_SCOPES.USERS_READ)); // admin kept
    });

    test("returns null for key owned by inactive user", async () => {
        // Deactivate the user, try to resolve
        await R.exec("UPDATE `user` SET active = 0 WHERE id = ?", [readOnlyUserID]);
        const result = await resolveAPIKey(`uk${customScopesKeyID}_${clearKeyCustom}`);
        assert.strictEqual(result, null);
        // Re-activate
        await R.exec("UPDATE `user` SET active = 1 WHERE id = ?", [readOnlyUserID]);
    });

    test("handles invalid JSON in permissions gracefully", async () => {
        // Temporarily set invalid JSON
        await R.exec("UPDATE api_key SET permissions = ? WHERE id = ?", ["not-json", apiKeyID]);
        const result = await resolveAPIKey(`uk${apiKeyID}_${clearKey}`);
        assert.ok(result);
        assert.deepStrictEqual(result.scopes, []);
        // Restore
        await R.exec("UPDATE api_key SET permissions = ? WHERE id = ?",
            [JSON.stringify([API_SCOPES.MONITORS_READ, API_SCOPES.MONITORS_WRITE]), apiKeyID]);
    });

    test("key with future expiry is valid", async () => {
        await R.exec("UPDATE api_key SET expires = ? WHERE id = ?", ["2099-12-31T23:59:59Z", apiKeyID]);
        const result = await resolveAPIKey(`uk${apiKeyID}_${clearKey}`);
        assert.ok(result);
        assert.strictEqual(result.user.id, adminUserID);
        // Restore
        await R.exec("UPDATE api_key SET expires = NULL WHERE id = ?", [apiKeyID]);
    });
});

describe("API Auth - apiCanAccessMonitor", () => {
    const { apiCanAccessMonitor } = require("../../server/modules/api-auth");

    test("admin can access any monitor", () => {
        const req = { apiUser: { id: 1 }, userRole: "admin" };
        const result = apiCanAccessMonitor(req, 999);
        assert.strictEqual(result, true);
    });
});

describe("API Auth - apiCanEditMonitor", () => {
    const { apiCanEditMonitor } = require("../../server/modules/api-auth");

    test("admin can edit any monitor", () => {
        const req = { apiUser: { id: 1 }, userRole: "admin" };
        const result = apiCanEditMonitor(req, 999);
        assert.strictEqual(result, true);
    });
});

describe("API Auth - apiGetAccessibleMonitorIDs", () => {
    const { apiGetAccessibleMonitorIDs } = require("../../server/modules/api-auth");

    test("admin returns null (all monitors)", () => {
        const req = { apiUser: { id: 1 }, userRole: "admin" };
        const result = apiGetAccessibleMonitorIDs(req);
        assert.strictEqual(result, null);
    });
});

describe("API Auth - apiKeyAuth middleware", () => {
    const { apiKeyAuth } = require("../../server/modules/api-auth");

    /**
     * Create a mock response object
     * @returns {object} Mock response with status tracking
     */
    function mockRes() {
        const r = {
            statusCode: null,
            body: null,
            /**
             * Set HTTP status code
             * @param {number} code Status code
             * @returns {object} Chainable response
             */
            status(code) {
                r.statusCode = code;
                return r;
            },
            /**
             * Send JSON response body
             * @param {object} obj JSON body
             */
            json(obj) {
                r.body = obj;
            },
        };
        return r;
    }

    test("returns 401 when Authorization header is missing", async () => {
        const req = { headers: {} };
        const res = mockRes();
        let nextCalled = false;
        await apiKeyAuth(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.strictEqual(res.statusCode, 401);
        assert.ok(res.body.msg.includes("Missing Authorization header"));
    });

    test("returns 401 for invalid key (within DB context)", async () => {
        // Note: apiKeyAuth calls resolveAPIKey which requires a DB.
        // The resolveAPIKey DB describe above covers invalid-key scenarios directly.
        // Here we just verify the middleware structure handles the error path.
        const req = { headers: { authorization: "Bearer invalid_not_uk_format" } };
        const res = mockRes();
        let nextCalled = false;
        // This key doesn't match uk{id}_{clearKey} format, so resolveAPIKey returns null
        // without querying DB (early return).
        await apiKeyAuth(req, res, () => {
            nextCalled = true;
        });
        assert.strictEqual(nextCalled, false);
        assert.ok(res.statusCode === 401 || res.statusCode === 429);
    });
});
