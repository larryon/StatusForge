/**
 * Add user_monitor table for direct user-to-monitor access assignments.
 * Allows assigning individual monitors or monitoring groups directly to users,
 * independent of permission groups.
 */
exports.up = function (knex) {
    return knex.schema
        .createTable("user_monitor", function (table) {
            table.increments("id");
            table.integer("user_id").unsigned().notNullable()
                .references("id").inTable("user").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("monitor_id").unsigned().notNullable()
                .references("id").inTable("monitor").onDelete("CASCADE").onUpdate("CASCADE");
            table.string("role", 20).notNullable().defaultTo("readonly");
            table.unique(["user_id", "monitor_id"]);
        });
};

exports.down = function (knex) {
    return knex.schema.dropTable("user_monitor");
};
