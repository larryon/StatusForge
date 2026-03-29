/**
 * Simplify user roles from 5-role system to 2-role system.
 * - Converts "full-admin" users to "admin"
 * - Converts all other roles (group-admin, group-readonly, monitor-admin, monitor-read-only) to "read-only"
 * - Drops permission_group, user_permission_group, and user_monitor tables
 * - Drops permission_group_id columns from monitor, status_page, maintenance, notification
 */
exports.up = function (knex) {
    return knex("user")
        .where("role", "full-admin")
        .update({ role: "admin" })
        .then(() => {
            return knex("user")
                .whereNotIn("role", ["admin"])
                .update({ role: "read-only" });
        })
        .then(() => {
            return knex.schema
                .alterTable("notification", function (table) {
                    table.dropColumn("permission_group_id");
                })
                .alterTable("maintenance", function (table) {
                    table.dropColumn("permission_group_id");
                })
                .alterTable("status_page", function (table) {
                    table.dropColumn("permission_group_id");
                })
                .alterTable("monitor", function (table) {
                    table.dropColumn("permission_group_id");
                });
        })
        .then(() => {
            return knex.schema
                .dropTableIfExists("user_monitor")
                .dropTableIfExists("user_permission_group")
                .dropTableIfExists("permission_group");
        });
};

exports.down = function (knex) {
    return knex.schema
        .createTable("permission_group", function (table) {
            table.increments("id");
            table.string("name", 255).notNullable().unique();
            table.text("description").nullable();
            table.boolean("active").notNullable().defaultTo(true);
            table.timestamp("created_date").defaultTo(knex.fn.now());
        })
        .createTable("user_permission_group", function (table) {
            table.increments("id");
            table.integer("user_id").unsigned().notNullable()
                .references("id").inTable("user").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("permission_group_id").unsigned().notNullable()
                .references("id").inTable("permission_group").onDelete("CASCADE").onUpdate("CASCADE");
            table.string("role", 20).notNullable().defaultTo("group-readonly");
            table.unique(["user_id", "permission_group_id"]);
        })
        .createTable("user_monitor", function (table) {
            table.increments("id");
            table.integer("user_id").unsigned().notNullable()
                .references("id").inTable("user").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("monitor_id").unsigned().notNullable()
                .references("id").inTable("monitor").onDelete("CASCADE").onUpdate("CASCADE");
            table.string("role", 20).notNullable().defaultTo("readonly");
            table.unique(["user_id", "monitor_id"]);
        })
        .alterTable("monitor", function (table) {
            table.integer("permission_group_id").unsigned().nullable();
        })
        .alterTable("status_page", function (table) {
            table.integer("permission_group_id").unsigned().nullable();
        })
        .alterTable("maintenance", function (table) {
            table.integer("permission_group_id").unsigned().nullable();
        })
        .alterTable("notification", function (table) {
            table.integer("permission_group_id").unsigned().nullable();
        })
        .then(() => {
            // Convert admin back to full-admin
            return knex("user")
                .where("role", "admin")
                .update({ role: "full-admin" });
        });
};
