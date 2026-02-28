exports.up = function (knex) {
    return knex.schema.alterTable("api_key", function (table) {
        // JSON array of permission scopes, e.g. ["monitors:read","monitors:write"]
        // NULL means "inherit all permissions from the owning user's role"
        table.text("permissions").defaultTo(null);
    });
};

exports.down = function (knex) {
    return knex.schema.alterTable("api_key", function (table) {
        table.dropColumn("permissions");
    });
};
