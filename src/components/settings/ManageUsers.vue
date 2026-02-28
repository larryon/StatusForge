<template>
    <div>
        <div class="add-btn">
            <button class="btn btn-primary me-2" type="button" @click="showAddDialog">
                <font-awesome-icon icon="plus" />
                {{ $t("Add User") }}
            </button>
        </div>

        <div>
            <span
                v-if="userList.length === 0"
                class="d-flex align-items-center justify-content-center my-3"
            >
                {{ $t("No users found") }}
            </span>

            <div v-for="user in userList" :key="user.id" class="item" :class="{ active: user.active }">
                <div class="left-part">
                    <div class="circle"></div>
                    <div class="info">
                        <div class="title">{{ user.username }}</div>
                        <div class="status">
                            <span class="badge" :class="roleBadgeClass(user.role)">{{ formatRole(user.role) }}</span>
                            <span v-if="!user.active" class="badge bg-secondary ms-1">{{ $t("Inactive") }}</span>
                        </div>
                        <div v-if="user.permissionGroups && user.permissionGroups.length > 0" class="groups mt-1">
                            <small class="text-muted">
                                {{ $t("Groups") }}: {{ user.permissionGroups.map(g => g.groupName).join(", ") }}
                            </small>
                        </div>
                        <div v-if="user.directMonitors && user.directMonitors.length > 0" class="monitors mt-1">
                            <small class="text-muted">
                                {{ $t("Monitors") }}: {{ user.directMonitors.map(m => m.monitorName).join(", ") }}
                            </small>
                        </div>
                    </div>
                </div>

                <div class="buttons">
                    <div class="btn-group" role="group">
                        <button class="btn btn-normal" @click="showEditDialog(user)">
                            <font-awesome-icon icon="edit" />
                            {{ $t("Edit") }}
                        </button>
                        <button class="btn btn-normal" @click="showMonitorsDialog(user)">
                            <font-awesome-icon icon="desktop" />
                            {{ $t("Monitors") }}
                        </button>
                        <button class="btn btn-normal" @click="showResetPasswordDialog(user)">
                            <font-awesome-icon icon="key" />
                            {{ $t("Reset Password") }}
                        </button>
                        <button
                            v-if="user.id !== currentUserID"
                            class="btn btn-danger"
                            @click="showDeleteDialog(user)"
                        >
                            <font-awesome-icon icon="trash" />
                            {{ $t("Delete") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add/Edit User Dialog -->
        <div ref="userDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ isEditing ? $t("Edit User") : $t("Add User") }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Username") }}</label>
                            <input v-model="dialogUser.username" type="text" class="form-control" required />
                        </div>
                        <div v-if="!isEditing" class="mb-3">
                            <label class="form-label">{{ $t("Password") }}</label>
                            <input v-model="dialogUser.password" type="password" class="form-control" required />
                        </div>
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Role") }}</label>
                            <select
                                v-model="dialogUser.role"
                                class="form-select"
                                :disabled="isEditing && dialogUser.id === currentUserID"
                            >
                                <option value="full-admin">{{ $t("Full Admin") }}</option>
                                <option value="group-admin">{{ $t("Group Admin") }}</option>
                                <option value="group-readonly">{{ $t("Group Read-Only") }}</option>
                                <option value="monitor-admin">{{ $t("Monitor Admin") }}</option>
                                <option value="monitor-read-only">{{ $t("Monitor Read-Only") }}</option>
                            </select>
                            <div v-if="isEditing && dialogUser.id === currentUserID" class="form-text text-warning">
                                {{ $t("cannotChangeOwnRole") }}
                            </div>
                            <div class="form-text">
                                <strong>{{ $t("Full Admin") }}</strong>: {{ $t("roleDescFullAdmin") }}<br>
                                <strong>{{ $t("Group Admin") }}</strong>: {{ $t("roleDescGroupAdmin") }}<br>
                                <strong>{{ $t("Group Read-Only") }}</strong>: {{ $t("roleDescGroupReadOnly") }}<br>
                                <strong>{{ $t("Monitor Admin") }}</strong>: {{ $t("roleDescMonitorAdmin") }}<br>
                                <strong>{{ $t("Monitor Read-Only") }}</strong>: {{ $t("roleDescMonitorReadOnly") }}
                            </div>
                        </div>
                        <div v-if="isGroupRole && permissionGroups.length > 0" class="mb-3">
                            <label class="form-label">{{ $t("Permission Groups") }}</label>
                            <div v-for="group in permissionGroups" :key="group.id" class="form-check">
                                <input
                                    :id="'group-' + group.id"
                                    v-model="dialogUser.selectedGroups"
                                    class="form-check-input"
                                    type="checkbox"
                                    :value="group.id"
                                />
                                <label :for="'group-' + group.id" class="form-check-label">
                                    {{ group.name }}
                                    <small v-if="group.description" class="text-muted">— {{ group.description }}</small>
                                </label>
                            </div>
                            <div class="form-text">
                                {{ $t("selectGroupsForUser") }}
                            </div>
                        </div>
                        <div v-if="isMonitorRole" class="mb-3">
                            <label class="form-label">{{ $t("Monitors") }}</label>
                            <div class="monitor-select-list">
                                <div v-if="allMonitors.length === 0" class="text-muted small">
                                    {{ $t("No monitors found") }}
                                </div>
                                <div v-for="m in sortedAllMonitors" :key="m.id" class="form-check">
                                    <input
                                        :id="'monitor-' + m.id"
                                        v-model="dialogUser.selectedMonitors"
                                        class="form-check-input"
                                        type="checkbox"
                                        :value="m.id"
                                    />
                                    <label :for="'monitor-' + m.id" class="form-check-label">
                                        <font-awesome-icon v-if="m.type === 'group'" icon="folder" class="me-1 text-warning" />
                                        {{ m.name }}
                                        <span v-if="m.type" class="badge bg-secondary ms-1">{{ m.type }}</span>
                                    </label>
                                </div>
                            </div>
                            <div class="form-text">
                                {{ $t("selectMonitorsForUser") }}
                            </div>
                        </div>
                        <div v-if="isEditing" class="mb-3">
                            <div class="form-check">
                                <input
                                    v-model="dialogUser.active"
                                    class="form-check-input"
                                    type="checkbox"
                                />
                                <label class="form-check-label">{{ $t("Active") }}</label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            {{ $t("Cancel") }}
                        </button>
                        <button type="button" class="btn btn-primary" @click="saveUser">
                            {{ $t("Save") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Reset Password Dialog -->
        <div ref="resetPasswordDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("Reset Password") }} - {{ resetPasswordUser.username }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">{{ $t("New Password") }}</label>
                            <input v-model="newPassword" type="password" class="form-control" required />
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            {{ $t("Cancel") }}
                        </button>
                        <button type="button" class="btn btn-primary" @click="resetPassword">
                            {{ $t("Save") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- User Monitors Dialog -->
        <div ref="userMonitorsDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("Direct Monitor Access") }} - {{ monitorsDialogUser.username }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Add monitor form -->
                        <div class="row mb-3">
                            <div class="col-5">
                                <select v-model="addMonitorID" class="form-select">
                                    <option value="">{{ $t("Select Monitor") }}</option>
                                    <optgroup :label="$t('Monitoring Groups')">
                                        <option
                                            v-for="m in availableGroupMonitors"
                                            :key="m.id"
                                            :value="m.id"
                                        >
                                            &#128193; {{ m.name }}
                                        </option>
                                    </optgroup>
                                    <optgroup :label="$t('Individual Monitors')">
                                        <option
                                            v-for="m in availableIndividualMonitors"
                                            :key="m.id"
                                            :value="m.id"
                                        >
                                            {{ m.name }}
                                        </option>
                                    </optgroup>
                                </select>
                            </div>
                            <div class="col-4">
                                <select v-model="addMonitorRole" class="form-select">
                                    <option value="admin">{{ $t("Admin") }}</option>
                                    <option value="readonly">{{ $t("Read-Only") }}</option>
                                </select>
                            </div>
                            <div class="col-3">
                                <button class="btn btn-primary w-100" @click="assignMonitor">
                                    <font-awesome-icon icon="plus" />
                                    {{ $t("Add") }}
                                </button>
                            </div>
                        </div>

                        <div v-if="userMonitorList.length > 0" class="mb-2 text-muted">
                            <small>
                                <font-awesome-icon icon="info-circle" />
                                {{ $t("monitorGroupInheritanceNote") }}
                            </small>
                        </div>

                        <!-- Monitor list -->
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>{{ $t("Monitor") }}</th>
                                    <th>{{ $t("Type") }}</th>
                                    <th>{{ $t("Role") }}</th>
                                    <th>{{ $t("Actions") }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-if="userMonitorList.length === 0">
                                    <td colspan="4" class="text-center text-muted">
                                        {{ $t("No monitors assigned") }}
                                    </td>
                                </tr>
                                <tr v-for="m in userMonitorList" :key="m.monitorID">
                                    <td>
                                        <font-awesome-icon v-if="m.monitorType === 'group'" icon="folder" class="me-1 text-warning" />
                                        {{ m.monitorName }}
                                    </td>
                                    <td>
                                        <span v-if="m.monitorType === 'group'" class="badge bg-warning text-dark">
                                            {{ $t("Monitoring Group") }}
                                        </span>
                                        <span v-else class="badge bg-secondary">
                                            {{ m.monitorType }}
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge" :class="m.role === 'admin' ? 'bg-danger' : 'bg-info'">
                                            {{ m.role === "admin" ? $t("Admin") : $t("Read-Only") }}
                                        </span>
                                    </td>
                                    <td>
                                        <button class="btn btn-sm btn-danger" @click="unassignMonitor(m.monitorID)">
                                            <font-awesome-icon icon="trash" />
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            {{ $t("Close") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Delete Confirm -->
        <Confirm ref="confirmDelete" btn-style="btn-danger" :yes-text="$t('Yes')" :no-text="$t('No')" @yes="deleteUser">
            {{ $t("deleteUserMsg") }}
        </Confirm>
    </div>
</template>

<script>
import { Modal } from "bootstrap";
import Confirm from "../Confirm.vue";

export default {
    components: {
        Confirm,
    },

    data() {
        return {
            userList: [],
            allMonitors: [],
            isEditing: false,
            permissionGroups: [],
            dialogUser: {
                username: "",
                password: "",
                role: "group-readonly",
                active: true,
                selectedGroups: [],
                selectedMonitors: [],
            },
            resetPasswordUser: {},
            newPassword: "",
            deleteUserID: null,
            currentUserID: null,
            monitorsDialogUser: {},
            userMonitorList: [],
            addMonitorID: "",
            addMonitorRole: "readonly",
        };
    },

    computed: {
        /**
         * Whether the selected role is a group-based role
         * @returns {boolean} True if group-admin or group-readonly
         */
        isGroupRole() {
            return this.dialogUser.role === "group-admin" || this.dialogUser.role === "group-readonly";
        },

        /**
         * Whether the selected role is a monitor-level role
         * @returns {boolean} True if monitor-admin or monitor-read-only
         */
        isMonitorRole() {
            return this.dialogUser.role === "monitor-admin" || this.dialogUser.role === "monitor-read-only";
        },

        /**
         * All monitors sorted: groups first, then individual, alphabetically
         * @returns {object[]} Sorted monitor list
         */
        sortedAllMonitors() {
            return [...this.allMonitors].sort((a, b) => {
                if (a.type === "group" && b.type !== "group") {
                    return -1;
                }
                if (a.type !== "group" && b.type === "group") {
                    return 1;
                }
                return a.name.localeCompare(b.name);
            });
        },

        /**
         * Group-type monitors not already assigned to the current user
         * @returns {object[]} Available group monitors
         */
        availableGroupMonitors() {
            const assignedIDs = this.userMonitorList.map(m => m.monitorID);
            return this.allMonitors.filter(m => m.type === "group" && !assignedIDs.includes(m.id));
        },

        /**
         * Individual monitors not already assigned to the current user
         * @returns {object[]} Available individual monitors
         */
        availableIndividualMonitors() {
            const assignedIDs = this.userMonitorList.map(m => m.monitorID);
            return this.allMonitors.filter(m => m.type !== "group" && !assignedIDs.includes(m.id));
        },
    },

    mounted() {
        this.loadUserList();
        this.loadPermissionGroups();
        this.loadAllMonitors();
        // Get current user ID from JWT
        const payload = this.$root.getJWTPayload();
        if (payload) {
            this.currentUserID = this.$root.socket.userID;
        }
    },

    methods: {
        /**
         * Load the list of users from the server
         * @returns {void}
         */
        loadUserList() {
            this.$root.getSocket().emit("getUserList", (res) => {
                if (res.ok) {
                    this.userList = res.users;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Get CSS class for role badge
         * @param {string} role User role
         * @returns {string} CSS class
         */
        roleBadgeClass(role) {
            if (role === "full-admin") {
                return "bg-danger";
            }
            if (role === "group-admin") {
                return "bg-warning text-dark";
            }
            if (role === "monitor-admin") {
                return "bg-success";
            }
            if (role === "monitor-read-only") {
                return "bg-primary";
            }
            return "bg-info";
        },

        /**
         * Format role text for display
         * @param {string} role User role
         * @returns {string} Formatted role text
         */
        formatRole(role) {
            const roleMap = {
                "full-admin": this.$t("Full Admin"),
                "group-admin": this.$t("Group Admin"),
                "group-readonly": this.$t("Group Read-Only"),
                "monitor-admin": this.$t("Monitor Admin"),
                "monitor-read-only": this.$t("Monitor Read-Only"),
            };
            return roleMap[role] || role;
        },

        /**
         * Load list of permission groups
         * @returns {void}
         */
        loadPermissionGroups() {
            this.$root.getSocket().emit("getPermissionGroupList", (res) => {
                if (res.ok) {
                    this.permissionGroups = res.groups;
                }
            });
        },

        /**
         * Show add user dialog
         * @returns {void}
         */
        showAddDialog() {
            this.isEditing = false;
            this.dialogUser = {
                username: "",
                password: "",
                role: "group-readonly",
                active: true,
                selectedGroups: [],
                selectedMonitors: [],
            };
            new Modal(this.$refs.userDialog).show();
        },

        /**
         * Show edit user dialog
         * @param {object} user User to edit
         * @returns {void}
         */
        showEditDialog(user) {
            this.isEditing = true;
            this.dialogUser = {
                id: user.id,
                username: user.username,
                role: user.role,
                active: !!user.active,
                selectedGroups: (user.permissionGroups || []).map(g => g.groupId),
                selectedMonitors: (user.directMonitors || []).map(m => m.monitorID),
            };
            new Modal(this.$refs.userDialog).show();
        },

        /**
         * Show reset password dialog
         * @param {object} user User to reset password for
         * @returns {void}
         */
        showResetPasswordDialog(user) {
            this.resetPasswordUser = user;
            this.newPassword = "";
            new Modal(this.$refs.resetPasswordDialog).show();
        },

        /**
         * Show delete user confirmation
         * @param {object} user User to delete
         * @returns {void}
         */
        showDeleteDialog(user) {
            this.deleteUserID = user.id;
            this.$refs.confirmDelete.show();
        },

        /**
         * Save user (add or edit)
         * @returns {void}
         */
        saveUser() {
            if (this.isEditing) {
                this.$root.getSocket().emit("editUser", this.dialogUser, (res) => {
                    if (res.ok) {
                        this.$root.toastRes(res);
                        this.syncGroupMemberships(this.dialogUser.id);
                        this.syncMonitorAssignments(this.dialogUser.id);
                        Modal.getInstance(this.$refs.userDialog)?.hide();
                        this.loadUserList();
                    } else {
                        this.$root.toastError(res.msg);
                    }
                });
            } else {
                this.$root.getSocket().emit("addUser", this.dialogUser, (res) => {
                    if (res.ok) {
                        this.$root.toastRes(res);
                        if (res.user && res.user.id) {
                            this.syncGroupMemberships(res.user.id);
                            this.syncMonitorAssignments(res.user.id);
                        }
                        Modal.getInstance(this.$refs.userDialog)?.hide();
                        this.loadUserList();
                    } else {
                        this.$root.toastError(res.msg);
                    }
                });
            }
        },

        /**
         * Sync permission group memberships for a user.
         * Adds user to selected groups and removes from unselected ones.
         * @param {number} userID User ID
         * @returns {void}
         */
        syncGroupMemberships(userID) {
            const selectedGroups = this.dialogUser.selectedGroups || [];

            // Only group-based roles need group memberships
            if (!this.isGroupRole) {
                return;
            }

            // Find the user's current groups
            const user = this.userList.find(u => u.id === userID);
            const currentGroupIDs = (user && user.permissionGroups || []).map(g => g.groupId);

            // Groups to add
            const toAdd = selectedGroups.filter(gid => !currentGroupIDs.includes(gid));
            // Groups to remove
            const toRemove = currentGroupIDs.filter(gid => !selectedGroups.includes(gid));

            const groupRole = this.dialogUser.role === "group-admin" ? "group-admin" : "group-readonly";

            for (const groupID of toAdd) {
                this.$root.getSocket().emit("addPermissionGroupMember", {
                    userID,
                    groupID,
                    role: groupRole,
                }, (res) => {
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                });
            }

            for (const groupID of toRemove) {
                this.$root.getSocket().emit("removePermissionGroupMember", {
                    userID,
                    groupID,
                }, (res) => {
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                });
            }

            // Reload user list after a short delay to pick up group changes
            setTimeout(() => this.loadUserList(), 500);
        },

        /**
         * Sync direct monitor assignments for a user.
         * Adds user to selected monitors and removes from unselected ones.
         * @param {number} userID User ID
         * @returns {void}
         */
        syncMonitorAssignments(userID) {
            const selectedMonitors = this.dialogUser.selectedMonitors || [];

            // Only monitor-level roles need direct monitor assignments
            if (!this.isMonitorRole) {
                return;
            }

            // Find the user's current monitor assignments
            const user = this.userList.find(u => u.id === userID);
            const currentMonitorIDs = (user && user.directMonitors || []).map(m => m.monitorID);

            // Monitors to add
            const toAdd = selectedMonitors.filter(mid => !currentMonitorIDs.includes(mid));
            // Monitors to remove
            const toRemove = currentMonitorIDs.filter(mid => !selectedMonitors.includes(mid));

            const monitorRole = this.dialogUser.role === "monitor-admin" ? "admin" : "readonly";

            for (const monitorID of toAdd) {
                this.$root.getSocket().emit("assignMonitorToUser", {
                    userID,
                    monitorID,
                    role: monitorRole,
                }, (res) => {
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                });
            }

            for (const monitorID of toRemove) {
                this.$root.getSocket().emit("unassignMonitorFromUser", {
                    userID,
                    monitorID,
                }, (res) => {
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                });
            }

            // Reload user list after a short delay to pick up monitor changes
            setTimeout(() => this.loadUserList(), 500);
        },

        /**
         * Reset a user's password
         * @returns {void}
         */
        resetPassword() {
            this.$root.getSocket().emit("resetUserPassword", {
                id: this.resetPasswordUser.id,
                newPassword: this.newPassword,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    Modal.getInstance(this.$refs.resetPasswordDialog)?.hide();
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Show monitors dialog for a user
         * @param {object} user User to manage monitors for
         * @returns {void}
         */
        showMonitorsDialog(user) {
            this.monitorsDialogUser = user;
            this.addMonitorID = "";
            this.addMonitorRole = "readonly";
            this.loadUserMonitors(user.id);
            this.loadAllMonitors();
            new Modal(this.$refs.userMonitorsDialog).show();
        },

        /**
         * Load all monitors for assignment dropdowns
         * @returns {void}
         */
        loadAllMonitors() {
            this.$root.getSocket().emit("getAllMonitorsList", (res) => {
                if (res.ok) {
                    this.allMonitors = res.monitors;
                }
            });
        },

        /**
         * Load direct monitor assignments for a user
         * @param {number} userID User ID
         * @returns {void}
         */
        loadUserMonitors(userID) {
            this.$root.getSocket().emit("getUserMonitors", userID, (res) => {
                if (res.ok) {
                    this.userMonitorList = res.monitors;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Assign a monitor directly to the current user
         * @returns {void}
         */
        assignMonitor() {
            if (!this.addMonitorID) {
                return;
            }
            this.$root.getSocket().emit("assignMonitorToUser", {
                userID: this.monitorsDialogUser.id,
                monitorID: parseInt(this.addMonitorID),
                role: this.addMonitorRole,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadUserMonitors(this.monitorsDialogUser.id);
                    this.addMonitorID = "";
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Remove a direct monitor assignment from the current user
         * @param {number} monitorID Monitor ID
         * @returns {void}
         */
        unassignMonitor(monitorID) {
            this.$root.getSocket().emit("unassignMonitorFromUser", {
                userID: this.monitorsDialogUser.id,
                monitorID,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadUserMonitors(this.monitorsDialogUser.id);
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Delete a user
         * @returns {void}
         */
        deleteUser() {
            this.$root.getSocket().emit("deleteUser", {
                id: this.deleteUserID,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadUserList();
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },
    },
};
</script>

<style lang="scss" scoped>
@import "../../assets/vars.scss";

.add-btn {
    padding-top: 20px;
    padding-bottom: 20px;
}

.item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 15px;
    border-bottom: 1px solid $dark-border-color;

    .left-part {
        display: flex;
        align-items: center;
        gap: 12px;

        .circle {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: $primary;
        }

        .title {
            font-weight: bold;
        }
    }

    &:not(.active) {
        .circle {
            background-color: $secondary-text;
        }
    }
}

.monitor-select-list {
    max-height: 250px;
    overflow-y: auto;
    border: 1px solid $dark-border-color;
    border-radius: 0.375rem;
    padding: 8px;
}
</style>
