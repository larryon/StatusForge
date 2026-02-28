const express = require("express");
const { R } = require("redbean-node");
const { log } = require("../../src/util");
const {
    apiKeyAuth,
    requireScope,
    requireAdmin,
    API_SCOPES,
    SCOPE_GROUPS,
    apiCanAccessMonitor,
    apiCanEditMonitor,
    apiGetAccessibleMonitorIDs,
} = require("../modules/api-auth");
const {
    ROLES,
    MONITOR_ROLES,
    getUserPermissionGroups,
    getUserDirectMonitors,
    canAccessGroup,
    canEditInGroup,
    assignMonitorToUser,
    getGroupMonitors,
    assignMonitorToGroup,
    unassignMonitorFromGroup,
} = require("../auth-permissions");
const Monitor = require("../model/monitor");
const { Notification } = require("../notification");
const Maintenance = require("../model/maintenance");
const User = require("../model/user");
const PermissionGroup = require("../model/permission_group");
const { DockerHost } = require("../docker");
const { Settings } = require("../settings");
const { UptimeKumaServer } = require("../uptime-kuma-server");
const APIKey = require("../model/api_key");
const passwordHash = require("../password-hash");
const { nanoid } = require("nanoid");
const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
dayjs.extend(utc);

const router = express.Router();

// All v1 API routes require API key auth
router.use("/api/v1", apiKeyAuth);

// ========================================================================
// MONITORS
// ========================================================================

/**
 * GET /api/v1/monitors
 * List all monitors accessible by the API key owner.
 */
router.get("/api/v1/monitors",
    requireScope(API_SCOPES.MONITORS_READ),
    async (req, res) => {
        try {
            const accessibleIDs = await apiGetAccessibleMonitorIDs(req);

            let query;
            let queryParams;
            if (accessibleIDs === null) {
                // Full-admin: see all
                query = " 1=1 ";
                queryParams = [];
            } else if (accessibleIDs.size === 0) {
                return res.json({ ok: true, monitors: [] });
            } else {
                const idList = [...accessibleIDs];
                const placeholders = idList.map(() => "?").join(",");
                query = ` id IN (${placeholders}) `;
                queryParams = [...idList];
            }

            const monitors = await R.find("monitor", query + "ORDER BY weight DESC, name", queryParams);
            const monitorData = monitors.map(m => ({ id: m.id, active: m.active, name: m.name }));
            const preloadData = await Monitor.preparePreloadData(monitorData);

            const isMonitorLevel = req.userRole === ROLES.MONITOR_ADMIN || req.userRole === ROLES.MONITOR_READONLY;
            const result = monitors.map(m => {
                const json = m.toJSON(preloadData);
                if (isMonitorLevel) {
                    json.parent = null;
                }
                return json;
            });

            res.json({ ok: true, monitors: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/monitors/:id
 * Get a single monitor by ID.
 */
router.get("/api/v1/monitors/:id",
    requireScope(API_SCOPES.MONITORS_READ),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanAccessMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied to this monitor." });
            }

            const monitor = await R.findOne("monitor", " id = ? ", [monitorID]);
            if (!monitor) {
                return res.status(404).json({ ok: false, msg: "Monitor not found." });
            }

            const preloadData = await Monitor.preparePreloadData([{ id: monitor.id, active: monitor.active, name: monitor.name }]);
            const json = monitor.toJSON(preloadData);

            const isMonitorLevel = req.userRole === ROLES.MONITOR_ADMIN || req.userRole === ROLES.MONITOR_READONLY;
            if (isMonitorLevel) {
                json.parent = null;
            }

            res.json({ ok: true, monitor: json });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/monitors
 * Create a new monitor.
 */
router.post("/api/v1/monitors",
    requireScope(API_SCOPES.MONITORS_WRITE),
    async (req, res) => {
        try {
            // Check if user role allows creating monitors
            const role = req.userRole;
            if (role === ROLES.GROUP_READONLY || role === ROLES.MONITOR_ADMIN || role === ROLES.MONITOR_READONLY) {
                return res.status(403).json({ ok: false, msg: "Your role does not allow creating monitors." });
            }

            const monitor = req.body;
            const bean = R.dispense("monitor");
            bean.import(monitor);

            // Serialize JSON array fields
            const jsonArrayFields = ["accepted_statuscodes", "kafkaProducerBrokers"];
            for (const field of jsonArrayFields) {
                if (Array.isArray(bean[field])) {
                    bean[field] = JSON.stringify(bean[field]);
                }
            }

            bean.user_id = req.apiUser.id;
            bean.validate();
            await R.store(bean);

            // Link notifications if provided
            if (Array.isArray(monitor.notificationIDList)) {
                for (const notifID of monitor.notificationIDList) {
                    await R.exec("INSERT INTO monitor_notification (monitor_id, notification_id) VALUES (?, ?)", [bean.id, notifID]);
                }
            }

            // Auto-assign to non-admin users via user_monitor
            if (role !== ROLES.FULL_ADMIN) {
                await R.exec(
                    "INSERT INTO user_monitor (user_id, monitor_id, role) VALUES (?, ?, 'admin')",
                    [req.apiUser.id, bean.id]
                );
            }

            res.status(201).json({ ok: true, monitorID: bean.id, msg: "Monitor created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/monitors/:id
 * Update (edit) a monitor.
 */
router.patch("/api/v1/monitors/:id",
    requireScope(API_SCOPES.MONITORS_WRITE),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanEditMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied. Cannot edit this monitor." });
            }

            const bean = await R.findOne("monitor", " id = ? ", [monitorID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Monitor not found." });
            }

            const updates = req.body;

            // Apply only provided fields
            const allowedFields = [
                "name", "description", "type", "url", "hostname", "port",
                "method", "interval", "retryInterval", "resendInterval",
                "maxretries", "maxredirects", "timeout", "keyword",
                "invertKeyword", "active", "upsideDown", "ignoreTls",
                "expiryNotification", "accepted_statuscodes",
                "dns_resolve_type", "dns_resolve_server",
                "docker_container", "docker_host", "proxyId",
                "mqttTopic", "mqttSuccessMessage", "mqttCheckType",
                "mqttUsername", "mqttPassword",
                "headers", "body", "basic_auth_user", "basic_auth_pass",
                "pushToken", "weight", "parent", "ipFamily",
                "grpcUrl", "grpcProtobuf", "grpcMethod", "grpcServiceName",
                "grpcBody", "grpcMetadata", "grpcEnableTls",
                "jsonPath", "jsonPathOperator", "expectedValue",
                "kafkaProducerTopic", "kafkaProducerBrokers", "kafkaProducerMessage",
                "kafkaProducerSsl", "kafkaProducerAllowAutoTopicCreation",
                "gamedigGivenPortOnly", "game",
                "screenshot", "cacheBust", "remote_browser",
                "conditions", "ping_numeric", "ping_count", "packetSize",
            ];

            for (const field of allowedFields) {
                if (updates[field] !== undefined) {
                    // Serialize JSON array fields
                    if (Array.isArray(updates[field]) && (field === "accepted_statuscodes" || field === "kafkaProducerBrokers")) {
                        bean[field] = JSON.stringify(updates[field]);
                    } else {
                        bean[field] = updates[field];
                    }
                }
            }

            bean.validate();
            await R.store(bean);

            res.json({ ok: true, monitorID: bean.id, msg: "Monitor updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/monitors/:id
 * Delete a monitor.
 */
router.delete("/api/v1/monitors/:id",
    requireScope(API_SCOPES.MONITORS_WRITE),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanEditMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied. Cannot delete this monitor." });
            }

            const monitor = await R.findOne("monitor", " id = ? ", [monitorID]);
            if (!monitor) {
                return res.status(404).json({ ok: false, msg: "Monitor not found." });
            }

            // Use the static delete method
            const UptimeKumaServer = require("../uptime-kuma-server").UptimeKumaServer;
            const server = UptimeKumaServer.getInstance();

            // Stop monitor if running
            if (server.monitorList[monitorID]) {
                server.monitorList[monitorID].stop();
                delete server.monitorList[monitorID];
            }

            await Monitor.deleteMonitor(monitorID, req.apiUser.id);

            res.json({ ok: true, msg: "Monitor deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/monitors/:id/pause
 * Pause a monitor.
 */
router.post("/api/v1/monitors/:id/pause",
    requireScope(API_SCOPES.MONITORS_WRITE),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanEditMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied." });
            }

            const UptimeKumaServer = require("../uptime-kuma-server").UptimeKumaServer;
            const server = UptimeKumaServer.getInstance();

            if (server.monitorList[monitorID]) {
                await server.monitorList[monitorID].stop();
            }

            await R.exec("UPDATE monitor SET active = 0 WHERE id = ? ", [monitorID]);

            res.json({ ok: true, msg: "Monitor paused." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/monitors/:id/resume
 * Resume a paused monitor.
 */
router.post("/api/v1/monitors/:id/resume",
    requireScope(API_SCOPES.MONITORS_WRITE),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanEditMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied." });
            }

            const UptimeKumaServer = require("../uptime-kuma-server").UptimeKumaServer;
            const server = UptimeKumaServer.getInstance();

            await R.exec("UPDATE monitor SET active = 1 WHERE id = ? ", [monitorID]);

            const monitor = await R.findOne("monitor", " id = ? ", [monitorID]);
            if (monitor) {
                server.monitorList[monitorID] = monitor;
                monitor.start(server.io);
            }

            res.json({ ok: true, msg: "Monitor resumed." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/monitors/:id/beats
 * Get heartbeats for a monitor within a time range.
 * Query params: hours (default: 24)
 */
router.get("/api/v1/monitors/:id/beats",
    requireScope(API_SCOPES.UPTIME_READ),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanAccessMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied." });
            }

            const hours = parseInt(req.query.hours) || 24;
            const period = dayjs.utc().subtract(hours, "hour").format("YYYY-MM-DD HH:mm:ss");

            const beats = await R.getAll(
                "SELECT * FROM heartbeat WHERE monitor_id = ? AND time > ? ORDER BY time DESC",
                [monitorID, period]
            );

            res.json({ ok: true, heartbeats: beats });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/monitors/:id/uptime
 * Get uptime percentage for a monitor.
 * Query params: hours (default: 24)
 */
router.get("/api/v1/monitors/:id/uptime",
    requireScope(API_SCOPES.UPTIME_READ),
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.id);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }

            if (!(await apiCanAccessMonitor(req, monitorID))) {
                return res.status(403).json({ ok: false, msg: "Access denied." });
            }

            const hours = parseInt(req.query.hours) || 24;
            const period = dayjs.utc().subtract(hours, "hour").format("YYYY-MM-DD HH:mm:ss");

            const result = await R.getRow(
                `SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS up_count
                 FROM heartbeat
                 WHERE monitor_id = ? AND time > ?`,
                [monitorID, period]
            );

            const uptime = result.total > 0 ? (result.up_count / result.total * 100).toFixed(4) : 0;

            res.json({
                ok: true,
                uptime: parseFloat(uptime),
                total: result.total,
                up: result.up_count,
                down: result.total - result.up_count,
                hours,
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// NOTIFICATIONS
// ========================================================================

/**
 * GET /api/v1/notifications
 * List all notifications accessible by the API key owner.
 */
router.get("/api/v1/notifications",
    requireScope(API_SCOPES.NOTIFICATIONS_READ),
    async (req, res) => {
        try {
            let notifications;
            if (req.userRole === ROLES.FULL_ADMIN) {
                notifications = await R.findAll("notification");
            } else {
                const groups = await getUserPermissionGroups(req.apiUser.id);
                const groupIDs = groups.map(g => g.groupId);
                if (groupIDs.length === 0) {
                    notifications = await R.find("notification", " user_id = ? ", [req.apiUser.id]);
                } else {
                    const placeholders = groupIDs.map(() => "?").join(",");
                    notifications = await R.find(
                        "notification",
                        ` user_id = ? OR permission_group_id IN (${placeholders}) `,
                        [req.apiUser.id, ...groupIDs]
                    );
                }
            }

            const result = notifications.map(n => {
                const data = {
                    id: n.id,
                    name: n.name,
                    active: n.active,
                    isDefault: n.is_default,
                    userID: n.user_id,
                };
                // Parse config but strip sensitive fields
                try {
                    const config = JSON.parse(n.config);
                    data.type = config.type;
                } catch (e) {
                    data.type = "unknown";
                }
                return data;
            });

            res.json({ ok: true, notifications: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/notifications
 * Create a new notification.
 */
router.post("/api/v1/notifications",
    requireScope(API_SCOPES.NOTIFICATIONS_WRITE),
    async (req, res) => {
        try {
            const notification = req.body;
            if (!notification.name || !notification.type) {
                return res.status(400).json({ ok: false, msg: "name and type are required." });
            }
            const bean = await Notification.save(notification, null, req.apiUser.id);
            res.status(201).json({ ok: true, id: bean.id, msg: "Notification created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/notifications/:id
 * Get a single notification by ID.
 */
router.get("/api/v1/notifications/:id",
    requireScope(API_SCOPES.NOTIFICATIONS_READ),
    async (req, res) => {
        try {
            const notifID = parseInt(req.params.id);
            if (isNaN(notifID)) {
                return res.status(400).json({ ok: false, msg: "Invalid notification ID." });
            }
            const bean = await R.findOne("notification", " id = ? ", [notifID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Notification not found." });
            }
            // Non-admin can only see own notifications
            if (req.userRole !== ROLES.FULL_ADMIN && bean.user_id !== req.apiUser.id) {
                return res.status(403).json({ ok: false, msg: "Access denied." });
            }
            const data = { id: bean.id, name: bean.name, active: bean.active, isDefault: bean.is_default, userID: bean.user_id };
            try {
                const config = JSON.parse(bean.config);
                data.type = config.type;
            } catch (_e) {
                data.type = "unknown";
            }
            res.json({ ok: true, notification: data });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/notifications/:id
 * Update an existing notification.
 */
router.patch("/api/v1/notifications/:id",
    requireScope(API_SCOPES.NOTIFICATIONS_WRITE),
    async (req, res) => {
        try {
            const notifID = parseInt(req.params.id);
            if (isNaN(notifID)) {
                return res.status(400).json({ ok: false, msg: "Invalid notification ID." });
            }
            const notification = req.body;
            const bean = await Notification.save(notification, notifID, req.apiUser.id);
            res.json({ ok: true, id: bean.id, msg: "Notification updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/notifications/:id
 * Delete a notification.
 */
router.delete("/api/v1/notifications/:id",
    requireScope(API_SCOPES.NOTIFICATIONS_WRITE),
    async (req, res) => {
        try {
            const notifID = parseInt(req.params.id);
            if (isNaN(notifID)) {
                return res.status(400).json({ ok: false, msg: "Invalid notification ID." });
            }

            await Notification.delete(notifID, req.apiUser.id);
            res.json({ ok: true, msg: "Notification deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// TAGS
// ========================================================================

/**
 * GET /api/v1/tags
 * List all tags.
 */
router.get("/api/v1/tags",
    requireScope(API_SCOPES.TAGS_READ),
    async (req, res) => {
        try {
            const tags = await R.findAll("tag");
            res.json({ ok: true, tags: tags.map(t => t.toJSON()) });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/tags
 * Create a tag.
 */
router.post("/api/v1/tags",
    requireScope(API_SCOPES.TAGS_WRITE),
    async (req, res) => {
        try {
            const { name, color } = req.body;
            if (!name) {
                return res.status(400).json({ ok: false, msg: "Tag name is required." });
            }
            const bean = R.dispense("tag");
            bean.name = name;
            bean.color = color || "#4B5563";
            await R.store(bean);
            res.status(201).json({ ok: true, tag: bean.toJSON() });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/tags/:id
 * Get a single tag by ID.
 */
router.get("/api/v1/tags/:id",
    requireScope(API_SCOPES.TAGS_READ),
    async (req, res) => {
        try {
            const tagID = parseInt(req.params.id);
            if (isNaN(tagID)) {
                return res.status(400).json({ ok: false, msg: "Invalid tag ID." });
            }
            const bean = await R.findOne("tag", " id = ? ", [tagID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Tag not found." });
            }
            res.json({ ok: true, tag: bean.toJSON() });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/tags/:id
 * Update a tag.
 */
router.patch("/api/v1/tags/:id",
    requireScope(API_SCOPES.TAGS_WRITE),
    async (req, res) => {
        try {
            const tagID = parseInt(req.params.id);
            if (isNaN(tagID)) {
                return res.status(400).json({ ok: false, msg: "Invalid tag ID." });
            }
            const bean = await R.findOne("tag", " id = ? ", [tagID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Tag not found." });
            }
            if (req.body.name !== undefined) {
                bean.name = req.body.name;
            }
            if (req.body.color !== undefined) {
                bean.color = req.body.color;
            }
            await R.store(bean);
            res.json({ ok: true, tag: bean.toJSON(), msg: "Tag updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/tags/:id
 * Delete a tag.
 */
router.delete("/api/v1/tags/:id",
    requireScope(API_SCOPES.TAGS_WRITE),
    async (req, res) => {
        try {
            const tagID = parseInt(req.params.id);
            if (isNaN(tagID)) {
                return res.status(400).json({ ok: false, msg: "Invalid tag ID." });
            }
            await R.exec("DELETE FROM tag WHERE id = ?", [tagID]);
            res.json({ ok: true, msg: "Tag deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// MAINTENANCE
// ========================================================================

/**
 * GET /api/v1/maintenance
 * List all maintenance windows accessible by the API key owner.
 */
router.get("/api/v1/maintenance",
    requireScope(API_SCOPES.MAINTENANCE_READ),
    async (req, res) => {
        try {
            let maintenanceList;
            if (req.userRole === ROLES.FULL_ADMIN) {
                maintenanceList = await R.findAll("maintenance", " ORDER BY id DESC ");
            } else {
                const groups = await getUserPermissionGroups(req.apiUser.id);
                const groupIDs = groups.map(g => g.groupId);
                if (groupIDs.length === 0) {
                    maintenanceList = [];
                } else {
                    const placeholders = groupIDs.map(() => "?").join(",");
                    maintenanceList = await R.find(
                        "maintenance",
                        ` permission_group_id IN (${placeholders}) ORDER BY id DESC `,
                        groupIDs
                    );
                }
            }

            const result = maintenanceList.map(m => m.toJSON());
            res.json({ ok: true, maintenance: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/maintenance/:id
 * Get a single maintenance window.
 */
router.get("/api/v1/maintenance/:id",
    requireScope(API_SCOPES.MAINTENANCE_READ),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }

            const maintenance = await R.findOne("maintenance", " id = ? ", [maintenanceID]);
            if (!maintenance) {
                return res.status(404).json({ ok: false, msg: "Maintenance not found." });
            }

            // Permission check
            if (req.userRole !== ROLES.FULL_ADMIN) {
                const hasAccess = await canAccessGroup(req.apiUser.id, maintenance.permission_group_id, req.userRole);
                if (!hasAccess && maintenance.user_id !== req.apiUser.id) {
                    return res.status(403).json({ ok: false, msg: "Access denied." });
                }
            }

            res.json({ ok: true, maintenance: await maintenance.toJSON() });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/maintenance
 * Create a new maintenance window.
 */
router.post("/api/v1/maintenance",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const obj = req.body;
            if (!obj.title) {
                return res.status(400).json({ ok: false, msg: "title is required." });
            }
            if (!obj.strategy) {
                obj.strategy = "manual";
            }
            if (obj.description === undefined) {
                obj.description = "";
            }
            if (!obj.dateRange) {
                obj.dateRange = [null, null];
            }
            if (!obj.timeRange) {
                obj.timeRange = [{ hours: 0, minutes: 0 }, { hours: 0, minutes: 0 }];
            }
            if (obj.active === undefined) {
                obj.active = true;
            }

            let bean = R.dispense("maintenance");
            bean.user_id = req.apiUser.id;
            await Maintenance.jsonToBean(bean, obj);
            await R.store(bean);

            const server = UptimeKumaServer.getInstance();
            server.maintenanceList[bean.id] = bean;
            await bean.run(true);

            res.status(201).json({ ok: true, id: bean.id, msg: "Maintenance created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/maintenance/:id
 * Update an existing maintenance window.
 */
router.patch("/api/v1/maintenance/:id",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }

            const bean = await R.findOne("maintenance", " id = ? ", [maintenanceID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Maintenance not found." });
            }

            // Permission check
            if (req.userRole !== ROLES.FULL_ADMIN) {
                const canEdit = await canEditInGroup(req.apiUser.id, bean.permission_group_id, req.userRole);
                if (!canEdit && bean.user_id !== req.apiUser.id) {
                    return res.status(403).json({ ok: false, msg: "Permission denied." });
                }
            }

            // Merge current values with partial update
            const currentJSON = await bean.toJSON();
            const merged = Object.assign({}, currentJSON, req.body);
            if (!merged.dateRange) {
                merged.dateRange = [null, null];
            }
            if (!merged.timeRange) {
                merged.timeRange = [{ hours: 0, minutes: 0 }, { hours: 0, minutes: 0 }];
            }

            await Maintenance.jsonToBean(bean, merged);
            await R.store(bean);

            const server = UptimeKumaServer.getInstance();
            server.maintenanceList[bean.id] = bean;
            await bean.run(true);

            res.json({ ok: true, id: bean.id, msg: "Maintenance updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/maintenance/:id
 * Delete a maintenance window.
 */
router.delete("/api/v1/maintenance/:id",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }

            const bean = await R.findOne("maintenance", " id = ? ", [maintenanceID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Maintenance not found." });
            }

            // Permission check
            if (req.userRole !== ROLES.FULL_ADMIN) {
                const canEdit = await canEditInGroup(req.apiUser.id, bean.permission_group_id, req.userRole);
                if (!canEdit && bean.user_id !== req.apiUser.id) {
                    return res.status(403).json({ ok: false, msg: "Permission denied." });
                }
            }

            const server = UptimeKumaServer.getInstance();
            if (server.maintenanceList[maintenanceID]) {
                server.maintenanceList[maintenanceID].stop();
                delete server.maintenanceList[maintenanceID];
            }

            await R.exec("DELETE FROM maintenance WHERE id = ?", [maintenanceID]);
            res.json({ ok: true, msg: "Maintenance deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/maintenance/:id/pause
 * Pause a maintenance window.
 */
router.post("/api/v1/maintenance/:id/pause",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }

            const bean = await R.findOne("maintenance", " id = ? ", [maintenanceID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Maintenance not found." });
            }

            bean.active = false;
            await R.store(bean);

            const server = UptimeKumaServer.getInstance();
            if (server.maintenanceList[maintenanceID]) {
                server.maintenanceList[maintenanceID].stop();
            }

            res.json({ ok: true, msg: "Maintenance paused." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/maintenance/:id/resume
 * Resume a paused maintenance window.
 */
router.post("/api/v1/maintenance/:id/resume",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }

            const bean = await R.findOne("maintenance", " id = ? ", [maintenanceID]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Maintenance not found." });
            }

            bean.active = true;
            await R.store(bean);

            const server = UptimeKumaServer.getInstance();
            server.maintenanceList[bean.id] = bean;
            await bean.run(true);

            res.json({ ok: true, msg: "Maintenance resumed." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/maintenance/:id/monitors
 * Get monitors associated with a maintenance window.
 */
router.get("/api/v1/maintenance/:id/monitors",
    requireScope(API_SCOPES.MAINTENANCE_READ),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }
            const rows = await R.getAll(
                "SELECT monitor_id FROM monitor_maintenance WHERE maintenance_id = ?",
                [maintenanceID]
            );
            res.json({ ok: true, monitors: rows.map(r => r.monitor_id) });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PUT /api/v1/maintenance/:id/monitors
 * Replace the monitors associated with a maintenance window.
 */
router.put("/api/v1/maintenance/:id/monitors",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }
            const monitors = req.body.monitors;
            if (!Array.isArray(monitors)) {
                return res.status(400).json({ ok: false, msg: "monitors must be an array of monitor IDs." });
            }
            await R.exec("DELETE FROM monitor_maintenance WHERE maintenance_id = ?", [maintenanceID]);
            for (const monitorID of monitors) {
                await R.exec(
                    "INSERT INTO monitor_maintenance (monitor_id, maintenance_id) VALUES (?, ?)",
                    [monitorID, maintenanceID]
                );
            }
            res.json({ ok: true, msg: "Maintenance monitors updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/maintenance/:id/status-pages
 * Get status pages associated with a maintenance window.
 */
router.get("/api/v1/maintenance/:id/status-pages",
    requireScope(API_SCOPES.MAINTENANCE_READ),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }
            const rows = await R.getAll(
                "SELECT status_page_id FROM maintenance_status_page WHERE maintenance_id = ?",
                [maintenanceID]
            );
            res.json({ ok: true, statusPages: rows.map(r => r.status_page_id) });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PUT /api/v1/maintenance/:id/status-pages
 * Replace the status pages associated with a maintenance window.
 */
router.put("/api/v1/maintenance/:id/status-pages",
    requireScope(API_SCOPES.MAINTENANCE_WRITE),
    async (req, res) => {
        try {
            const maintenanceID = parseInt(req.params.id);
            if (isNaN(maintenanceID)) {
                return res.status(400).json({ ok: false, msg: "Invalid maintenance ID." });
            }
            const statusPages = req.body.statusPages;
            if (!Array.isArray(statusPages)) {
                return res.status(400).json({ ok: false, msg: "statusPages must be an array of status page IDs." });
            }
            await R.exec("DELETE FROM maintenance_status_page WHERE maintenance_id = ?", [maintenanceID]);
            for (const spID of statusPages) {
                await R.exec(
                    "INSERT INTO maintenance_status_page (status_page_id, maintenance_id) VALUES (?, ?)",
                    [spID, maintenanceID]
                );
            }
            res.json({ ok: true, msg: "Maintenance status pages updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// STATUS PAGES
// ========================================================================

/**
 * GET /api/v1/status-pages
 * List all status pages.
 */
router.get("/api/v1/status-pages",
    requireScope(API_SCOPES.STATUS_PAGES_READ),
    async (req, res) => {
        try {
            let statusPages;
            if (req.userRole === ROLES.FULL_ADMIN) {
                statusPages = await R.findAll("status_page");
            } else {
                const groups = await getUserPermissionGroups(req.apiUser.id);
                const groupIDs = groups.map(g => g.groupId);
                if (groupIDs.length === 0) {
                    statusPages = [];
                } else {
                    const placeholders = groupIDs.map(() => "?").join(",");
                    statusPages = await R.find(
                        "status_page",
                        ` permission_group_id IN (${placeholders}) `,
                        groupIDs
                    );
                }
            }

            const result = statusPages.map(sp => ({
                id: sp.id,
                slug: sp.slug,
                title: sp.title,
                description: sp.description,
                published: !!sp.published,
                icon: sp.icon,
            }));

            res.json({ ok: true, statusPages: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/status-pages/:slug
 * Get a single status page by slug.
 */
router.get("/api/v1/status-pages/:slug",
    requireScope(API_SCOPES.STATUS_PAGES_READ),
    async (req, res) => {
        try {
            const slug = req.params.slug;
            const statusPage = await R.findOne("status_page", " slug = ? ", [slug]);
            if (!statusPage) {
                return res.status(404).json({ ok: false, msg: "Status page not found." });
            }

            // Permission check
            if (req.userRole !== ROLES.FULL_ADMIN && statusPage.permission_group_id) {
                const hasAccess = await canAccessGroup(req.apiUser.id, statusPage.permission_group_id, req.userRole);
                if (!hasAccess) {
                    return res.status(403).json({ ok: false, msg: "Access denied." });
                }
            }

            const jsonData = statusPage.toJSON ? statusPage.toJSON() : {
                id: statusPage.id,
                slug: statusPage.slug,
                title: statusPage.title,
                description: statusPage.description,
                icon: statusPage.icon,
                theme: statusPage.theme,
                published: !!statusPage.published,
            };

            // Fetch groups with their monitors
            const groups = await R.find("group", " status_page_id = ? ORDER BY weight ", [statusPage.id]);
            const groupsJSON = [];
            for (const group of groups) {
                const monitorRows = await R.getAll(
                    "SELECT monitor_id, send_url, custom_url, weight FROM monitor_group WHERE group_id = ? ORDER BY weight",
                    [group.id]
                );
                groupsJSON.push({
                    id: group.id,
                    name: group.name,
                    weight: group.weight,
                    monitors: monitorRows.map(m => ({
                        monitorID: m.monitor_id,
                        sendUrl: !!m.send_url,
                        customUrl: m.custom_url,
                        weight: m.weight,
                    })),
                });
            }

            // Fetch incidents
            const incidents = await R.find("incident", " status_page_id = ? ORDER BY created_date DESC ", [statusPage.id]);
            const incidentsJSON = incidents.map(inc => ({
                id: inc.id,
                title: inc.title,
                content: inc.content,
                style: inc.style,
                pin: !!inc.pin,
                active: !!inc.active,
                createdDate: inc.created_date,
                lastUpdatedDate: inc.last_updated_date,
            }));

            res.json({
                ok: true,
                statusPage: jsonData,
                groups: groupsJSON,
                incidents: incidentsJSON,
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/status-pages
 * Create a new status page. Requires full-admin.
 */
router.post("/api/v1/status-pages",
    requireScope(API_SCOPES.STATUS_PAGES_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const { title, slug } = req.body;
            if (!title) {
                return res.status(400).json({ ok: false, msg: "title is required." });
            }
            if (!slug) {
                return res.status(400).json({ ok: false, msg: "slug is required." });
            }

            const normalizedSlug = slug.trim().toLowerCase();
            if (!normalizedSlug.match(/^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/)) {
                return res.status(400).json({ ok: false, msg: "Invalid slug format. Use alphanumeric with hyphens." });
            }

            const existing = await R.findOne("status_page", " slug = ? ", [normalizedSlug]);
            if (existing) {
                return res.status(409).json({ ok: false, msg: "Slug already exists." });
            }

            let bean = R.dispense("status_page");
            bean.slug = normalizedSlug;
            bean.title = title;
            bean.theme = "auto";
            bean.icon = "";
            bean.published = true;
            bean.search_engine_index = false;
            bean.show_powered_by = true;
            bean.modified_date = R.isoDateTime();
            bean.created_date = R.isoDateTime();
            await R.store(bean);

            res.status(201).json({ ok: true, id: bean.id, slug: bean.slug, msg: "Status page created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/status-pages/:slug
 * Update a status page's config, groups, and monitors.
 */
router.patch("/api/v1/status-pages/:slug",
    requireScope(API_SCOPES.STATUS_PAGES_WRITE),
    async (req, res) => {
        try {
            const slug = req.params.slug;
            const bean = await R.findOne("status_page", " slug = ? ", [slug]);
            if (!bean) {
                return res.status(404).json({ ok: false, msg: "Status page not found." });
            }

            // Permission check
            if (req.userRole !== ROLES.FULL_ADMIN && bean.permission_group_id) {
                const canEdit = await canEditInGroup(req.apiUser.id, bean.permission_group_id, req.userRole);
                if (!canEdit) {
                    return res.status(403).json({ ok: false, msg: "Permission denied." });
                }
            }

            const config = req.body;

            // Map config fields to bean
            if (config.title !== undefined) {
                bean.title = config.title;
            }
            if (config.description !== undefined) {
                bean.description = config.description;
            }
            if (config.icon !== undefined) {
                bean.icon = config.icon;
            }
            if (config.theme !== undefined) {
                bean.theme = config.theme;
            }
            if (config.published !== undefined) {
                bean.published = config.published;
            }
            if (config.searchEngineIndex !== undefined) {
                bean.search_engine_index = config.searchEngineIndex;
            }
            if (config.showTags !== undefined) {
                bean.show_tags = config.showTags;
            }
            if (config.footerText !== undefined) {
                bean.footer_text = config.footerText;
            }
            if (config.customCSS !== undefined) {
                bean.custom_css = config.customCSS;
            }
            if (config.showPoweredBy !== undefined) {
                bean.show_powered_by = config.showPoweredBy;
            }
            if (config.showCertificateExpiry !== undefined) {
                bean.show_certificate_expiry = config.showCertificateExpiry;
            }
            if (config.showOnlyLastHeartbeat !== undefined) {
                bean.show_only_last_heartbeat = config.showOnlyLastHeartbeat;
            }
            if (config.autoRefreshInterval !== undefined) {
                bean.autoRefreshInterval = config.autoRefreshInterval;
            }
            if (config.rssTitle !== undefined) {
                bean.rss_title = config.rssTitle;
            }
            if (config.permissionGroupId !== undefined) {
                bean.permission_group_id = config.permissionGroupId;
            }
            if (config.analyticsId !== undefined) {
                bean.analytics_id = config.analyticsId;
            }
            if (config.analyticsScriptUrl !== undefined) {
                bean.analytics_script_url = config.analyticsScriptUrl;
            }
            if (config.analyticsType !== undefined) {
                const validTypes = ["google", "umami", "plausible", "matomo"];
                if (config.analyticsType && !validTypes.includes(config.analyticsType)) {
                    return res.status(400).json({ ok: false, msg: "Invalid analyticsType." });
                }
                bean.analytics_type = config.analyticsType;
            }
            bean.modified_date = R.isoDateTime();
            await R.store(bean);

            // Update groups/monitors if provided
            if (Array.isArray(config.groups)) {
                const submittedGroupIDs = [];
                for (const groupData of config.groups) {
                    let groupBean;
                    if (groupData.id) {
                        groupBean = await R.findOne("group", " id = ? AND status_page_id = ? ", [groupData.id, bean.id]);
                    }
                    if (!groupBean) {
                        groupBean = R.dispense("group");
                        groupBean.status_page_id = bean.id;
                        groupBean.public = true;
                    }
                    groupBean.name = groupData.name || "Services";
                    groupBean.weight = groupData.weight || 0;
                    await R.store(groupBean);
                    submittedGroupIDs.push(groupBean.id);

                    // Replace monitors in this group
                    await R.exec("DELETE FROM monitor_group WHERE group_id = ?", [groupBean.id]);
                    if (Array.isArray(groupData.monitors)) {
                        for (const [idx, mon] of groupData.monitors.entries()) {
                            const mgBean = R.dispense("monitor_group");
                            mgBean.monitor_id = mon.monitorID || mon.id;
                            mgBean.group_id = groupBean.id;
                            mgBean.weight = mon.weight !== undefined ? mon.weight : idx;
                            mgBean.send_url = mon.sendUrl ? 1 : 0;
                            mgBean.custom_url = mon.customUrl || null;
                            await R.store(mgBean);
                        }
                    }
                }
                // Delete orphan groups
                if (submittedGroupIDs.length > 0) {
                    const placeholders = submittedGroupIDs.map(() => "?").join(",");
                    await R.exec(
                        `DELETE FROM \`group\` WHERE id NOT IN (${placeholders}) AND status_page_id = ?`,
                        [...submittedGroupIDs, bean.id]
                    );
                } else {
                    await R.exec("DELETE FROM `group` WHERE status_page_id = ?", [bean.id]);
                }
            }

            res.json({ ok: true, slug: bean.slug, msg: "Status page updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/status-pages/:slug
 * Delete a status page. Requires full-admin.
 */
router.delete("/api/v1/status-pages/:slug",
    requireScope(API_SCOPES.STATUS_PAGES_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const slug = req.params.slug;
            const statusPage = await R.findOne("status_page", " slug = ? ", [slug]);
            if (!statusPage) {
                return res.status(404).json({ ok: false, msg: "Status page not found." });
            }

            const statusPageID = statusPage.id;

            // Reset entry page if needed
            const server = UptimeKumaServer.getInstance();
            if (server.entryPage === "statusPage-" + slug) {
                server.entryPage = "dashboard";
                await Settings.setSettings("general", { entryPage: "dashboard" });
            }

            // Cascade delete
            await R.exec("DELETE FROM incident WHERE status_page_id = ?", [statusPageID]);
            await R.exec("DELETE FROM `group` WHERE status_page_id = ?", [statusPageID]);
            await R.exec("DELETE FROM status_page WHERE id = ?", [statusPageID]);

            res.json({ ok: true, msg: "Status page deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/status-pages/:slug/incidents
 * Create or update an incident on a status page.
 */
router.post("/api/v1/status-pages/:slug/incidents",
    requireScope(API_SCOPES.STATUS_PAGES_WRITE),
    async (req, res) => {
        try {
            const slug = req.params.slug;
            const statusPage = await R.findOne("status_page", " slug = ? ", [slug]);
            if (!statusPage) {
                return res.status(404).json({ ok: false, msg: "Status page not found." });
            }

            const { title, content, style } = req.body;
            if (!title || !content) {
                return res.status(400).json({ ok: false, msg: "title and content are required." });
            }

            const validStyles = ["info", "warning", "danger", "primary", "light", "dark"];
            const incidentStyle = style && validStyles.includes(style) ? style : "info";

            let incidentBean = R.dispense("incident");
            incidentBean.title = title;
            incidentBean.content = content;
            incidentBean.style = incidentStyle;
            incidentBean.pin = true;
            incidentBean.active = true;
            incidentBean.status_page_id = statusPage.id;
            incidentBean.created_date = R.isoDateTime();
            await R.store(incidentBean);

            res.status(201).json({ ok: true, id: incidentBean.id, msg: "Incident created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/status-pages/:slug/incidents/:incidentId
 * Delete an incident from a status page.
 */
router.delete("/api/v1/status-pages/:slug/incidents/:incidentId",
    requireScope(API_SCOPES.STATUS_PAGES_WRITE),
    async (req, res) => {
        try {
            const slug = req.params.slug;
            const incidentId = parseInt(req.params.incidentId);
            if (isNaN(incidentId)) {
                return res.status(400).json({ ok: false, msg: "Invalid incident ID." });
            }

            const statusPage = await R.findOne("status_page", " slug = ? ", [slug]);
            if (!statusPage) {
                return res.status(404).json({ ok: false, msg: "Status page not found." });
            }

            const incident = await R.findOne("incident", " id = ? AND status_page_id = ? ", [incidentId, statusPage.id]);
            if (!incident) {
                return res.status(404).json({ ok: false, msg: "Incident not found." });
            }

            await R.trash(incident);
            res.json({ ok: true, msg: "Incident deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// UPTIME SUMMARY
// ========================================================================

/**
 * GET /api/v1/uptime
 * Get uptime summary for all accessible monitors.
 * Query params: hours (default: 24)
 */
router.get("/api/v1/uptime",
    requireScope(API_SCOPES.UPTIME_READ),
    async (req, res) => {
        try {
            const hours = parseInt(req.query.hours) || 24;
            const period = dayjs.utc().subtract(hours, "hour").format("YYYY-MM-DD HH:mm:ss");
            const accessibleIDs = await apiGetAccessibleMonitorIDs(req);

            let whereClause;
            let params;
            if (accessibleIDs === null) {
                whereClause = "time > ?";
                params = [period];
            } else if (accessibleIDs.size === 0) {
                return res.json({ ok: true, monitors: [] });
            } else {
                const idList = [...accessibleIDs];
                const placeholders = idList.map(() => "?").join(",");
                whereClause = `monitor_id IN (${placeholders}) AND time > ?`;
                params = [...idList, period];
            }

            const rows = await R.getAll(
                `SELECT
                    monitor_id,
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS up_count,
                    ROUND(AVG(ping), 2) AS avg_ping
                 FROM heartbeat
                 WHERE ${whereClause}
                 GROUP BY monitor_id`,
                params
            );

            const result = rows.map(r => ({
                monitorID: r.monitor_id,
                uptime: r.total > 0 ? parseFloat((r.up_count / r.total * 100).toFixed(4)) : 0,
                total: r.total,
                up: r.up_count,
                down: r.total - r.up_count,
                avgPing: r.avg_ping,
            }));

            res.json({ ok: true, monitors: result, hours });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// DOCKER HOSTS
// ========================================================================

/**
 * GET /api/v1/docker-hosts
 * List docker hosts (full-admin or read scope).
 */
router.get("/api/v1/docker-hosts",
    requireScope(API_SCOPES.DOCKER_READ),
    async (req, res) => {
        try {
            const dockerHosts = await R.findAll("docker_host", " ORDER BY name ");
            const result = dockerHosts.map(d => ({
                id: d.id,
                name: d.name,
                dockerType: d.docker_type,
                dockerDaemon: d.docker_daemon,
                userID: d.user_id,
            }));
            res.json({ ok: true, dockerHosts: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/docker-hosts/:id
 * Get a single docker host.
 */
router.get("/api/v1/docker-hosts/:id",
    requireScope(API_SCOPES.DOCKER_READ),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid docker host ID." });
            }
            const host = await R.findOne("docker_host", " id = ? ", [id]);
            if (!host) {
                return res.status(404).json({ ok: false, msg: "Docker host not found." });
            }
            res.json({
                ok: true,
                dockerHost: {
                    id: host.id,
                    name: host.name,
                    dockerType: host.docker_type,
                    dockerDaemon: host.docker_daemon,
                    userID: host.user_id,
                },
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/docker-hosts
 * Create a new docker host.
 */
router.post("/api/v1/docker-hosts",
    requireScope(API_SCOPES.DOCKER_WRITE),
    async (req, res) => {
        try {
            const { name, dockerType, dockerDaemon } = req.body;
            if (!name) {
                return res.status(400).json({ ok: false, msg: "name is required." });
            }

            const dockerHost = {
                name,
                dockerType: dockerType || "socket",
                dockerDaemon: dockerDaemon || "",
            };

            const bean = await DockerHost.save(dockerHost, null, req.apiUser.id);
            res.status(201).json({ ok: true, id: bean.id, msg: "Docker host created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/docker-hosts/:id
 * Update a docker host.
 */
router.patch("/api/v1/docker-hosts/:id",
    requireScope(API_SCOPES.DOCKER_WRITE),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid docker host ID." });
            }

            const existing = await R.findOne("docker_host", " id = ? ", [id]);
            if (!existing) {
                return res.status(404).json({ ok: false, msg: "Docker host not found." });
            }

            const dockerHost = {
                name: req.body.name || existing.name,
                dockerType: req.body.dockerType || existing.docker_type,
                dockerDaemon: req.body.dockerDaemon !== undefined ? req.body.dockerDaemon : existing.docker_daemon,
            };

            await DockerHost.save(dockerHost, id, req.apiUser.id);
            res.json({ ok: true, id, msg: "Docker host updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/docker-hosts/:id
 * Delete a docker host.
 */
router.delete("/api/v1/docker-hosts/:id",
    requireScope(API_SCOPES.DOCKER_WRITE),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid docker host ID." });
            }

            await DockerHost.delete(id, req.apiUser.id);
            res.json({ ok: true, msg: "Docker host deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// USERS (full-admin only)
// ========================================================================

/**
 * GET /api/v1/users
 * List all users.
 */
router.get("/api/v1/users",
    requireScope(API_SCOPES.USERS_READ),
    requireAdmin,
    async (req, res) => {
        try {
            const users = await R.findAll("user");
            const result = [];
            for (const user of users) {
                const groups = await getUserPermissionGroups(user.id);
                const directMonitors = await getUserDirectMonitors(user.id);
                result.push({
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    active: !!user.active,
                    twofa: !!user.twofa_status,
                    createdDate: user.created_date,
                    permissionGroups: groups,
                    directMonitors,
                });
            }
            res.json({ ok: true, users: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/users/:id
 * Get a single user.
 */
router.get("/api/v1/users/:id",
    requireScope(API_SCOPES.USERS_READ),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid user ID." });
            }
            const user = await R.findOne("user", " id = ? ", [id]);
            if (!user) {
                return res.status(404).json({ ok: false, msg: "User not found." });
            }
            const groups = await getUserPermissionGroups(user.id);
            const directMonitors = await getUserDirectMonitors(user.id);
            res.json({
                ok: true,
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    active: !!user.active,
                    twofa: !!user.twofa_status,
                    createdDate: user.created_date,
                    permissionGroups: groups,
                    directMonitors,
                },
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/users
 * Create a new user. Requires full-admin.
 */
router.post("/api/v1/users",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const { username, password, role } = req.body;
            if (!username || !password) {
                return res.status(400).json({ ok: false, msg: "username and password are required." });
            }

            const validRoles = Object.values(ROLES);
            if (role && !validRoles.includes(role)) {
                return res.status(400).json({ ok: false, msg: "Invalid role. Valid: " + validRoles.join(", ") });
            }

            const user = await User.createUser(username, password, role || ROLES.GROUP_READONLY, req.apiUser.id);
            res.status(201).json({ ok: true, id: user.id, msg: "User created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/users/:id
 * Update a user's info (username, role, active). Requires full-admin.
 */
router.patch("/api/v1/users/:id",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid user ID." });
            }

            const updates = {};
            if (req.body.username !== undefined) {
                updates.username = req.body.username;
            }
            if (req.body.role !== undefined) {
                const validRoles = Object.values(ROLES);
                if (!validRoles.includes(req.body.role)) {
                    return res.status(400).json({ ok: false, msg: "Invalid role." });
                }
                updates.role = req.body.role;
            }
            if (req.body.active !== undefined) {
                updates.active = req.body.active;
            }

            await User.updateUser(id, updates);
            res.json({ ok: true, id, msg: "User updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/users/:id
 * Delete a user. Requires full-admin.
 */
router.delete("/api/v1/users/:id",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid user ID." });
            }

            await User.deleteUser(id);
            res.json({ ok: true, msg: "User deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/users/:id/reset-password
 * Reset a user's password. Requires full-admin.
 */
router.post("/api/v1/users/:id/reset-password",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid user ID." });
            }
            const { newPassword } = req.body;
            if (!newPassword) {
                return res.status(400).json({ ok: false, msg: "newPassword is required." });
            }

            await User.resetPassword(id, newPassword);
            res.json({ ok: true, msg: "Password reset." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PUT /api/v1/users/:id/monitors
 * Assign direct monitors to a user. Body: { monitors: [{ monitorID, role }] }
 */
router.put("/api/v1/users/:id/monitors",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid user ID." });
            }

            const user = await R.findOne("user", " id = ? ", [id]);
            if (!user) {
                return res.status(404).json({ ok: false, msg: "User not found." });
            }

            const monitors = req.body.monitors;
            if (!Array.isArray(monitors)) {
                return res.status(400).json({ ok: false, msg: "monitors must be an array of { monitorID, role }." });
            }

            // Remove all existing direct monitor assignments
            await R.exec("DELETE FROM user_monitor WHERE user_id = ?", [id]);

            // Re-assign
            for (const entry of monitors) {
                const monitorID = entry.monitorID || entry.id;
                const role = entry.role || MONITOR_ROLES.ADMIN;
                if (!Object.values(MONITOR_ROLES).includes(role)) {
                    return res.status(400).json({ ok: false, msg: `Invalid monitor role: ${role}` });
                }
                await assignMonitorToUser(id, monitorID, role);
            }

            res.json({ ok: true, msg: "User monitors updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// API KEYS (self-service)
// ========================================================================

/**
 * GET /api/v1/api-keys
 * List API keys belonging to the current user.
 */
router.get("/api/v1/api-keys",
    requireScope(API_SCOPES.API_KEYS_READ),
    async (req, res) => {
        try {
            let keys;
            if (req.userRole === ROLES.FULL_ADMIN) {
                keys = await R.findAll("api_key");
            } else {
                keys = await R.find("api_key", " user_id = ? ", [req.apiUser.id]);
            }

            const result = keys.map(k => ({
                id: k.id,
                name: k.name,
                userID: k.user_id,
                active: !!k.active,
                expires: k.expires,
                createdDate: k.created_date,
                status: k.getStatus ? k.getStatus() : (k.active ? "active" : "inactive"),
                permissions: k.permissions ? JSON.parse(k.permissions) : null,
            }));

            res.json({ ok: true, apiKeys: result });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/api-keys/scopes
 * List all available API scopes and scope groups.
 */
router.get("/api/v1/api-keys/scopes",
    requireScope(API_SCOPES.API_KEYS_READ),
    async (req, res) => {
        try {
            const { SCOPE_GROUPS, getScopesForRole } = require("../modules/api-auth");
            res.json({
                ok: true,
                scopes: Object.values(API_SCOPES),
                scopeGroups: SCOPE_GROUPS,
                roleScopesForCurrentUser: getScopesForRole(req.userRole),
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/api-keys
 * Create a new API key. Returns the clear-text key once only.
 */
router.post("/api/v1/api-keys",
    requireScope(API_SCOPES.API_KEYS_WRITE),
    async (req, res) => {
        try {
            const { name, expires, permissions } = req.body;
            if (!name) {
                return res.status(400).json({ ok: false, msg: "name is required." });
            }

            // Resolve permissions
            let resolvedPerms = null;
            if (typeof permissions === "string" && SCOPE_GROUPS[permissions]) {
                resolvedPerms = SCOPE_GROUPS[permissions];
            } else if (Array.isArray(permissions)) {
                resolvedPerms = permissions;
            }

            const clearKey = nanoid(40);
            const hashedKey = await passwordHash.generate(clearKey);

            const keyData = {
                key: hashedKey,
                name,
                active: true,
                expires: expires || null,
                permissions: resolvedPerms,
            };

            const bean = await APIKey.save(keyData, req.apiUser.id);
            const formattedKey = "uk" + bean.id + "_" + clearKey;

            // Enable API auth
            await Settings.set("apiKeysEnabled", true);

            res.status(201).json({
                ok: true,
                id: bean.id,
                key: formattedKey,
                msg: "API key created. Store this key securely — it cannot be retrieved again.",
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/api-keys/:id
 * Delete an API key.
 */
router.delete("/api/v1/api-keys/:id",
    requireScope(API_SCOPES.API_KEYS_WRITE),
    async (req, res) => {
        try {
            const keyID = parseInt(req.params.id);
            if (isNaN(keyID)) {
                return res.status(400).json({ ok: false, msg: "Invalid API key ID." });
            }

            // Allow full-admin to delete any key, otherwise only own keys
            let where;
            let params;
            if (req.userRole === ROLES.FULL_ADMIN) {
                where = " id = ? ";
                params = [keyID];
            } else {
                where = " id = ? AND user_id = ? ";
                params = [keyID, req.apiUser.id];
            }

            const key = await R.findOne("api_key", where, params);
            if (!key) {
                return res.status(404).json({ ok: false, msg: "API key not found." });
            }

            await R.exec("DELETE FROM api_key WHERE id = ?", [keyID]);
            res.json({ ok: true, msg: "API key deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/api-keys/:id/enable
 * Enable an API key.
 */
router.post("/api/v1/api-keys/:id/enable",
    requireScope(API_SCOPES.API_KEYS_WRITE),
    async (req, res) => {
        try {
            const keyID = parseInt(req.params.id);
            if (isNaN(keyID)) {
                return res.status(400).json({ ok: false, msg: "Invalid API key ID." });
            }
            await R.exec("UPDATE api_key SET active = 1 WHERE id = ?", [keyID]);
            res.json({ ok: true, msg: "API key enabled." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/api-keys/:id/disable
 * Disable an API key.
 */
router.post("/api/v1/api-keys/:id/disable",
    requireScope(API_SCOPES.API_KEYS_WRITE),
    async (req, res) => {
        try {
            const keyID = parseInt(req.params.id);
            if (isNaN(keyID)) {
                return res.status(400).json({ ok: false, msg: "Invalid API key ID." });
            }
            await R.exec("UPDATE api_key SET active = 0 WHERE id = ?", [keyID]);
            res.json({ ok: true, msg: "API key disabled." });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// SETTINGS (full-admin only)
// ========================================================================

/**
 * GET /api/v1/settings
 * Get application settings.
 */
router.get("/api/v1/settings",
    requireScope(API_SCOPES.SETTINGS_READ),
    requireAdmin,
    async (req, res) => {
        try {
            const data = await Settings.getSettings("general");
            res.json({ ok: true, settings: data });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/settings
 * Update application settings.
 */
router.patch("/api/v1/settings",
    requireScope(API_SCOPES.SETTINGS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const data = req.body;
            await Settings.setSettings("general", data);
            res.json({ ok: true, msg: "Settings updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// PERMISSION GROUPS
// ========================================================================

/**
 * GET /api/v1/permission-groups
 * List all permission groups.
 */
router.get("/api/v1/permission-groups",
    requireScope(API_SCOPES.USERS_READ),
    async (req, res) => {
        try {
            let groups;
            if (req.userRole === ROLES.FULL_ADMIN) {
                groups = await PermissionGroup.list();
            } else {
                groups = await PermissionGroup.listForUser(req.apiUser.id);
            }
            res.json({ ok: true, permissionGroups: groups });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/permission-groups/:id
 * Get a single permission group with members.
 */
router.get("/api/v1/permission-groups/:id",
    requireScope(API_SCOPES.USERS_READ),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }

            const group = await R.findOne("permission_group", " id = ? ", [id]);
            if (!group) {
                return res.status(404).json({ ok: false, msg: "Permission group not found." });
            }

            // Permission check for non-admin
            if (req.userRole !== ROLES.FULL_ADMIN) {
                const hasAccess = await canAccessGroup(req.apiUser.id, id, req.userRole);
                if (!hasAccess) {
                    return res.status(403).json({ ok: false, msg: "Access denied." });
                }
            }

            const members = await PermissionGroup.getMembers(id);
            const monitors = await getGroupMonitors(id);

            const groupJSON = group.toJSON ? await group.toJSON() : {
                id: group.id,
                name: group.name,
                description: group.description,
                active: !!group.active,
            };

            res.json({
                ok: true,
                permissionGroup: groupJSON,
                members,
                monitors,
            });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/permission-groups
 * Create a permission group. Requires full-admin.
 */
router.post("/api/v1/permission-groups",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const { name, description } = req.body;
            if (!name) {
                return res.status(400).json({ ok: false, msg: "name is required." });
            }
            const group = await PermissionGroup.create(name, description || "");
            res.status(201).json({ ok: true, id: group.id, msg: "Permission group created." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * PATCH /api/v1/permission-groups/:id
 * Update a permission group. Requires full-admin.
 */
router.patch("/api/v1/permission-groups/:id",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            await PermissionGroup.update(id, req.body);
            res.json({ ok: true, id, msg: "Permission group updated." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/permission-groups/:id
 * Delete a permission group. Requires full-admin.
 */
router.delete("/api/v1/permission-groups/:id",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            await PermissionGroup.delete(id);
            res.json({ ok: true, msg: "Permission group deleted." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/permission-groups/:id/members
 * List members of a permission group.
 */
router.get("/api/v1/permission-groups/:id/members",
    requireScope(API_SCOPES.USERS_READ),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            const members = await PermissionGroup.getMembers(id);
            res.json({ ok: true, members });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/permission-groups/:id/members
 * Add a member to a permission group. Body: { userID, role }
 */
router.post("/api/v1/permission-groups/:id/members",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const groupID = parseInt(req.params.id);
            if (isNaN(groupID)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            const { userID, role } = req.body;
            if (!userID) {
                return res.status(400).json({ ok: false, msg: "userID is required." });
            }
            await PermissionGroup.addMember(userID, groupID, role || ROLES.GROUP_READONLY);
            res.status(201).json({ ok: true, msg: "Member added to group." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/permission-groups/:id/members/:userId
 * Remove a member from a permission group.
 */
router.delete("/api/v1/permission-groups/:id/members/:userId",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const groupID = parseInt(req.params.id);
            const userID = parseInt(req.params.userId);
            if (isNaN(groupID) || isNaN(userID)) {
                return res.status(400).json({ ok: false, msg: "Invalid group or user ID." });
            }
            await PermissionGroup.removeMember(userID, groupID);
            res.json({ ok: true, msg: "Member removed from group." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * GET /api/v1/permission-groups/:id/monitors
 * List monitors assigned to a permission group.
 */
router.get("/api/v1/permission-groups/:id/monitors",
    requireScope(API_SCOPES.USERS_READ),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            const monitors = await getGroupMonitors(id);
            res.json({ ok: true, monitors });
        } catch (e) {
            log.error("api", e.message);
            res.status(500).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * POST /api/v1/permission-groups/:id/monitors
 * Assign a monitor to a permission group. Body: { monitorID }
 */
router.post("/api/v1/permission-groups/:id/monitors",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const groupID = parseInt(req.params.id);
            if (isNaN(groupID)) {
                return res.status(400).json({ ok: false, msg: "Invalid group ID." });
            }
            const { monitorID } = req.body;
            if (!monitorID) {
                return res.status(400).json({ ok: false, msg: "monitorID is required." });
            }
            await assignMonitorToGroup(monitorID, groupID);
            res.status(201).json({ ok: true, msg: "Monitor assigned to group." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

/**
 * DELETE /api/v1/permission-groups/:id/monitors/:monitorId
 * Unassign a monitor from a permission group.
 */
router.delete("/api/v1/permission-groups/:id/monitors/:monitorId",
    requireScope(API_SCOPES.USERS_WRITE),
    requireAdmin,
    async (req, res) => {
        try {
            const monitorID = parseInt(req.params.monitorId);
            if (isNaN(monitorID)) {
                return res.status(400).json({ ok: false, msg: "Invalid monitor ID." });
            }
            await unassignMonitorFromGroup(monitorID);
            res.json({ ok: true, msg: "Monitor unassigned from group." });
        } catch (e) {
            log.error("api", e.message);
            res.status(400).json({ ok: false, msg: e.message });
        }
    }
);

// ========================================================================
// INFO / HEALTH
// ========================================================================

/**
 * GET /api/v1/info
 * Get server info and API key owner info.
 */
router.get("/api/v1/info", async (req, res) => {
    try {
        res.json({
            ok: true,
            version: require("../../package.json").version,
            user: {
                id: req.apiUser.id,
                username: req.apiUser.username,
                role: req.userRole,
            },
            scopes: [...req.apiScopes],
        });
    } catch (e) {
        log.error("api", e.message);
        res.status(500).json({ ok: false, msg: e.message });
    }
});

module.exports = router;
