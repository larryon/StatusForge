const { BeanModel } = require("redbean-node/dist/bean-model");
const passwordHash = require("../password-hash");
const { R } = require("redbean-node");
const jwt = require("jsonwebtoken");
const { shake256, SHAKE256_LENGTH } = require("../util-server");
const { getUserPermissionGroups, getUserDirectMonitors } = require("../auth-permissions");

class User extends BeanModel {
    /**
     * Reset user password
     * Fix #1510, as in the context reset-password.js, there is no auto model mapping. Call this static function instead.
     * @param {number} userID ID of user to update
     * @param {string} newPassword Users new password
     * @returns {Promise<void>}
     */
    static async resetPassword(userID, newPassword) {
        await R.exec("UPDATE `user` SET password = ? WHERE id = ? ", [
            await passwordHash.generate(newPassword),
            userID,
        ]);
    }

    /**
     * Reset this users password
     * @param {string} newPassword Users new password
     * @returns {Promise<void>}
     */
    async resetPassword(newPassword) {
        const hashedPassword = await passwordHash.generate(newPassword);

        await R.exec("UPDATE `user` SET password = ? WHERE id = ? ", [hashedPassword, this.id]);

        this.password = hashedPassword;
    }

    /**
     * Create a new JWT for a user
     * @param {User} user The User to create a JsonWebToken for
     * @param {string} jwtSecret The key used to sign the JsonWebToken
     * @returns {string} the JsonWebToken as a string
     */
    static createJWT(user, jwtSecret) {
        return jwt.sign(
            {
                username: user.username,
                h: shake256(user.password, SHAKE256_LENGTH),
            },
            jwtSecret
        );
    }

    /**
     * Convert user bean to JSON, excluding sensitive fields
     * @returns {Promise<object>} User JSON object
     */
    async toPublicJSON() {
        const groups = await getUserPermissionGroups(this.id);
        const directMonitors = await getUserDirectMonitors(this.id);
        return {
            id: this.id,
            username: this.username,
            role: this.role,
            active: this.active,
            twofa_status: this.twofa_status,
            created_by: this.created_by,
            created_date: this.created_date,
            permissionGroups: groups,
            directMonitors: directMonitors,
        };
    }

    /**
     * Create a new user
     * @param {string} username Username
     * @param {string} password Plain text password
     * @param {string} role User role (full-admin, group-admin, group-readonly)
     * @param {number|null} createdBy ID of user creating this user
     * @returns {Promise<Bean>} Created user bean
     */
    static async createUser(username, password, role = "group-readonly", createdBy = null) {
        // Check if username already exists
        const existing = await R.findOne("user", " username = ? ", [username]);
        if (existing) {
            throw new Error("Username already exists.");
        }

        let user = R.dispense("user");
        user.username = username;
        user.password = await passwordHash.generate(password);
        user.role = role;
        user.active = 1;
        user.created_by = createdBy;
        await R.store(user);
        return user;
    }

    /**
     * Update a user
     * @param {number} userID ID of user to update
     * @param {object} updates Fields to update
     * @returns {Promise<Bean>} Updated user bean
     */
    static async updateUser(userID, updates) {
        return await R.exec("SELECT 1", []).then(async () => {
            const knex = R.knex;
            return await knex.transaction(async (trx) => {
                let user = await R.findOne("user", " id = ? ", [userID]);
                if (!user) {
                    throw new Error("User not found.");
                }

                if (updates.username !== undefined) {
                    const existing = await R.findOne("user", " username = ? AND id != ? ", [updates.username, userID]);
                    if (existing) {
                        throw new Error("Username already exists.");
                    }
                    user.username = updates.username;
                }

                if (updates.role !== undefined) {
                    // Prevent changing the last full-admin to a different role
                    if (user.role === "full-admin" && updates.role !== "full-admin") {
                        const adminCount = await trx("user").where({ role: "full-admin", active: 1 }).count("id as count").first();
                        if (adminCount.count <= 1) {
                            throw new Error("Cannot change the role of the last full-admin user.");
                        }
                    }
                    user.role = updates.role;
                }

                if (updates.active !== undefined) {
                    // Prevent deactivating the last full-admin
                    if (user.role === "full-admin" && !updates.active && user.active) {
                        const adminCount = await trx("user").where({ role: "full-admin", active: 1 }).count("id as count").first();
                        if (adminCount.count <= 1) {
                            throw new Error("Cannot deactivate the last full-admin user.");
                        }
                    }
                    user.active = updates.active ? 1 : 0;
                }

                await R.store(user);
                return user;
            });
        });
    }

    /**
     * Delete a user
     * @param {number} userID ID of user to delete
     * @returns {Promise<void>}
     */
    static async deleteUser(userID) {
        const knex = R.knex;
        await knex.transaction(async (trx) => {
            const user = await R.findOne("user", " id = ? ", [userID]);
            if (!user) {
                throw new Error("User not found.");
            }
            if (user.role === "full-admin") {
                const adminCount = await trx("user").where({ role: "full-admin", active: 1 }).count("id as count").first();
                if (adminCount.count <= 1) {
                    throw new Error("Cannot delete the last full-admin user.");
                }
            }
            await R.trash(user);
        });
    }

    /**
     * List all users with public info
     * @returns {Promise<object[]>} List of user JSON objects
     */
    static async listUsers() {
        const users = await R.findAll("user", " ORDER BY id ASC ");
        const result = [];
        for (const user of users) {
            result.push(await user.toPublicJSON());
        }
        return result;
    }
}

module.exports = User;
