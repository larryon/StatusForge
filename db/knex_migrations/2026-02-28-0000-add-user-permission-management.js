/**
 * Add user permission management tables and columns.
 * - Creates permission_group table
 * - Creates user_permission_group join table
 * - Adds role column to user table
 * - Adds permission_group_id to monitor, status_page, maintenance, notification tables
 * - Seeds existing user as full-admin
 * - Creates a "Default" permission group and assigns existing monitors to it
 */
exports.up = function (knex) {
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
        .alterTable("user", function (table) {
            table.string("role", 20).notNullable().defaultTo("group-readonly");
            table.integer("created_by").unsigned().nullable()
                .references("id").inTable("user").onDelete("SET NULL").onUpdate("CASCADE");
            table.timestamp("created_date").nullable();
        })
        .alterTable("monitor", function (table) {
            table.integer("permission_group_id").unsigned().nullable()
                .references("id").inTable("permission_group").onDelete("SET NULL").onUpdate("CASCADE");
        })
        .alterTable("status_page", function (table) {
            table.integer("permission_group_id").unsigned().nullable()
                .references("id").inTable("permission_group").onDelete("SET NULL").onUpdate("CASCADE");
        })
        .alterTable("maintenance", function (table) {
            table.integer("permission_group_id").unsigned().nullable()
                .references("id").inTable("permission_group").onDelete("SET NULL").onUpdate("CASCADE");
        })
        .alterTable("notification", function (table) {
            table.integer("permission_group_id").unsigned().nullable()
                .references("id").inTable("permission_group").onDelete("SET NULL").onUpdate("CASCADE");
        })
        .then(async () => {
            // Set all existing users to full-admin and backfill created_date
            await knex("user").update({
                role: "full-admin",
                created_date: knex.fn.now(),
            });

            // Create a "Default" permission group
            const [defaultGroupId] = await knex("permission_group").insert({
                name: "Default",
                description: "Default permission group for all existing resources",
                active: true,
            });

            // Assign all existing monitors to the Default group
            await knex("monitor").update({ permission_group_id: defaultGroupId });

            // Assign all existing status pages to the Default group
            await knex("status_page").update({ permission_group_id: defaultGroupId });

            // Assign all existing maintenances to the Default group
            await knex("maintenance").update({ permission_group_id: defaultGroupId });

            // Assign all existing notifications to the Default group
            await knex("notification").update({ permission_group_id: defaultGroupId });

            // Assign existing full-admin users to the Default group as group-admin
            const users = await knex("user").select("id");
            for (const user of users) {
                await knex("user_permission_group").insert({
                    user_id: user.id,
                    permission_group_id: defaultGroupId,
                    role: "group-admin",
                });
            }
        });
};

exports.down = function (knex) {
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
        })
        .dropTable("user_permission_group")
        .dropTable("permission_group")
        .alterTable("user", function (table) {
            table.dropColumn("role");
            table.dropColumn("created_by");
            table.dropColumn("created_date");
        });
};
