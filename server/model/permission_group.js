const { BeanModel } = require("redbean-node/dist/bean-model");
const { R } = require("redbean-node");

class PermissionGroup extends BeanModel {
    /**
     * Convert permission group to JSON
     * @returns {Promise<object>} JSON representation
     */
    async toJSON() {
        const counts = await R.getRow(
            `SELECT
                (SELECT COUNT(*) FROM user_permission_group WHERE permission_group_id = ?) AS memberCount,
                (SELECT COUNT(*) FROM monitor WHERE permission_group_id = ?) AS monitorCount,
                (SELECT COUNT(*) FROM status_page WHERE permission_group_id = ?) AS statusPageCount,
                (SELECT COUNT(*) FROM maintenance WHERE permission_group_id = ?) AS maintenanceCount`,
            [this.id, this.id, this.id, this.id]
        );

        return {
            id: this.id,
            name: this.name,
            description: this.description,
            active: this.active,
            created_date: this.created_date,
            memberCount: counts.memberCount,
            monitorCount: counts.monitorCount,
            statusPageCount: counts.statusPageCount,
            maintenanceCount: counts.maintenanceCount,
        };
    }

    /**
     * Create a new permission group
     * @param {string} name Group name
     * @param {string} description Group description
     * @returns {Promise<Bean>} Created group bean
     */
    static async create(name, description = "") {
        const existing = await R.findOne("permission_group", " name = ? ", [name]);
        if (existing) {
            throw new Error("A permission group with this name already exists.");
        }

        let bean = R.dispense("permission_group");
        bean.name = name;
        bean.description = description;
        bean.active = 1;
        await R.store(bean);
        return bean;
    }

    /**
     * Update a permission group
     * @param {number} groupID ID of group to update
     * @param {object} updates Fields to update
     * @returns {Promise<Bean>} Updated group bean
     */
    static async update(groupID, updates) {
        let bean = await R.findOne("permission_group", " id = ? ", [groupID]);
        if (!bean) {
            throw new Error("Permission group not found.");
        }

        if (updates.name !== undefined) {
            const existing = await R.findOne("permission_group", " name = ? AND id != ? ", [updates.name, groupID]);
            if (existing) {
                throw new Error("A permission group with this name already exists.");
            }
            bean.name = updates.name;
        }

        if (updates.description !== undefined) {
            bean.description = updates.description;
        }

        if (updates.active !== undefined) {
            bean.active = updates.active ? 1 : 0;
        }

        await R.store(bean);
        return bean;
    }

    /**
     * Delete a permission group
     * @param {number} groupID ID of group to delete
     * @returns {Promise<void>}
     */
    static async delete(groupID) {
        let bean = await R.findOne("permission_group", " id = ? ", [groupID]);
        if (!bean) {
            throw new Error("Permission group not found.");
        }

        // Set any resources in this group to NULL
        await R.exec("UPDATE monitor SET permission_group_id = NULL WHERE permission_group_id = ?", [groupID]);
        await R.exec("UPDATE status_page SET permission_group_id = NULL WHERE permission_group_id = ?", [groupID]);
        await R.exec("UPDATE maintenance SET permission_group_id = NULL WHERE permission_group_id = ?", [groupID]);
        await R.exec("UPDATE notification SET permission_group_id = NULL WHERE permission_group_id = ?", [groupID]);

        await R.trash(bean);
    }

    /**
     * List all permission groups
     * @returns {Promise<object[]>} List of group JSON objects
     */
    static async list() {
        const groups = await R.findAll("permission_group", " ORDER BY name ASC ");
        const result = [];
        for (const group of groups) {
            result.push(await group.toJSON());
        }
        return result;
    }

    /**
     * List permission groups that a user belongs to
     * @param {number} userID ID of the user
     * @returns {Promise<object[]>} List of group JSON objects
     */
    static async listForUser(userID) {
        const groups = await R.find("permission_group",
            " id IN (SELECT permission_group_id FROM user_permission_group WHERE user_id = ?) ORDER BY name ASC ",
            [userID]
        );
        const result = [];
        for (const group of groups) {
            result.push(await group.toJSON());
        }
        return result;
    }

    /**
     * Get members of a permission group
     * @param {number} groupID ID of group
     * @returns {Promise<object[]>} List of members with roles
     */
    static async getMembers(groupID) {
        const rows = await R.getAll(
            `SELECT u.id, u.username, u.role AS globalRole, u.active, upg.role AS groupRole
             FROM user u
             JOIN user_permission_group upg ON upg.user_id = u.id
             WHERE upg.permission_group_id = ?
             ORDER BY u.username ASC`,
            [groupID]
        );
        return rows;
    }

    /**
     * Add a user to a permission group
     * @param {number} userID ID of user
     * @param {number} groupID ID of group
     * @param {string} role Role in the group (group-admin or group-readonly)
     * @returns {Promise<void>}
     */
    static async addMember(userID, groupID, role = "group-readonly") {
        const existing = await R.getRow(
            "SELECT id FROM user_permission_group WHERE user_id = ? AND permission_group_id = ?",
            [userID, groupID]
        );
        if (existing) {
            // Update role instead
            await R.exec(
                "UPDATE user_permission_group SET role = ? WHERE user_id = ? AND permission_group_id = ?",
                [role, userID, groupID]
            );
            return;
        }

        let bean = R.dispense("user_permission_group");
        bean.user_id = userID;
        bean.permission_group_id = groupID;
        bean.role = role;
        await R.store(bean);
    }

    /**
     * Remove a user from a permission group
     * @param {number} userID ID of user
     * @param {number} groupID ID of group
     * @returns {Promise<void>}
     */
    static async removeMember(userID, groupID) {
        await R.exec(
            "DELETE FROM user_permission_group WHERE user_id = ? AND permission_group_id = ?",
            [userID, groupID]
        );
    }
}

module.exports = PermissionGroup;
