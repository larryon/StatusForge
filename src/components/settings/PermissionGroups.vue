<template>
    <div>
        <div class="permission-groups-help mb-3">
            <p class="text-muted mb-2">{{ $t("permissionGroupsDescription") }}</p>
            <div class="alert alert-info small mb-0">
                <strong>{{ $t("twoWaysToGrantAccess") }}</strong>
                <ol class="mb-0 mt-1">
                    <li>{{ $t("accessMethodGroup") }}</li>
                    <li>{{ $t("accessMethodDirect") }}</li>
                </ol>
            </div>
        </div>

        <div class="add-btn">
            <button class="btn btn-primary me-2" type="button" @click="showAddDialog">
                <font-awesome-icon icon="plus" />
                {{ $t("Add Permission Group") }}
            </button>
            <button class="btn btn-outline-primary" type="button" @click="showWizard">
                <font-awesome-icon icon="magic" />
                {{ $t("quickSetupWizard") }}
            </button>
        </div>

        <div>
            <span
                v-if="groupList.length === 0"
                class="d-flex align-items-center justify-content-center my-3"
            >
                {{ $t("No permission groups found") }}
            </span>

            <div v-for="group in groupList" :key="group.id" class="item">
                <div class="left-part">
                    <div class="info">
                        <div class="title">{{ group.name }}</div>
                        <div v-if="group.description" class="description text-muted">
                            {{ group.description }}
                        </div>
                        <div class="stats mt-1">
                            <span class="badge bg-secondary me-1">
                                {{ $t("membersCount", { count: group.memberCount }) }}
                            </span>
                            <span class="badge bg-secondary me-1">
                                {{ $t("monitorsCount", { count: group.monitorCount }) }}
                            </span>
                            <span class="badge bg-secondary me-1">
                                {{ $t("statusPagesCount", { count: group.statusPageCount }) }}
                            </span>
                            <span class="badge bg-secondary me-1">
                                {{ $t("maintenanceCount", { count: group.maintenanceCount }) }}
                            </span>
                        </div>
                    </div>
                </div>

                <div class="buttons">
                    <div class="btn-group" role="group">
                        <button class="btn btn-normal" @click="showEditDialog(group)">
                            <font-awesome-icon icon="edit" />
                            {{ $t("Edit") }}
                        </button>
                        <button class="btn btn-normal" @click="showMembersDialog(group)">
                            <font-awesome-icon icon="users" />
                            {{ $t("Members") }}
                        </button>
                        <button class="btn btn-normal" @click="showMonitorsDialog(group)">
                            <font-awesome-icon icon="desktop" />
                            {{ $t("Monitors") }}
                        </button>
                        <button class="btn btn-danger" @click="showDeleteDialog(group)">
                            <font-awesome-icon icon="trash" />
                            {{ $t("Delete") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add/Edit Group Dialog -->
        <div ref="groupDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ isEditing ? $t("Edit Permission Group") : $t("Add Permission Group") }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Name") }}</label>
                            <input v-model="dialogGroup.name" type="text" class="form-control" required />
                        </div>
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Description") }}</label>
                            <textarea v-model="dialogGroup.description" class="form-control" rows="3"></textarea>
                        </div>
                        <div v-if="isEditing" class="mb-3">
                            <div class="form-check">
                                <input
                                    v-model="dialogGroup.active"
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
                        <button type="button" class="btn btn-primary" @click="saveGroup">
                            {{ $t("Save") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Members Dialog -->
        <div ref="membersDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("Members") }} - {{ currentGroup.name }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Add member form -->
                        <div class="row mb-3">
                            <div class="col-5">
                                <select v-model="addMemberUserIDs" class="form-select" multiple size="4">
                                    <option
                                        v-for="user in availableUsers"
                                        :key="user.id"
                                        :value="user.id"
                                    >
                                        {{ user.username }}
                                    </option>
                                </select>
                                <small class="text-muted">{{ $t("bulkSelectHint") }}</small>
                            </div>
                            <div class="col-4">
                                <select v-model="addMemberRole" class="form-select">
                                    <option value="group-admin">{{ $t("Group Admin") }}</option>
                                    <option value="group-readonly">{{ $t("Group Read-Only") }}</option>
                                </select>
                            </div>
                            <div class="col-3">
                                <button class="btn btn-primary w-100" :disabled="addMemberUserIDs.length === 0" @click="addMembersBulk">
                                    <font-awesome-icon icon="plus" />
                                    {{ $t("Add") }} <span v-if="addMemberUserIDs.length > 1">({{ addMemberUserIDs.length }})</span>
                                </button>
                            </div>
                        </div>

                        <!-- Members list -->
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>{{ $t("Username") }}</th>
                                    <th>{{ $t("Global Role") }}</th>
                                    <th>{{ $t("Group Role") }}</th>
                                    <th>{{ $t("Actions") }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-if="memberList.length === 0">
                                    <td colspan="4" class="text-center text-muted">
                                        {{ $t("No members") }}
                                    </td>
                                </tr>
                                <tr v-for="member in memberList" :key="member.id">
                                    <td>{{ member.username }}</td>
                                    <td>
                                        <span class="badge" :class="roleBadgeClass(member.globalRole)">
                                            {{ formatRole(member.globalRole) }}
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge" :class="roleBadgeClass(member.groupRole)">
                                            {{ formatRole(member.groupRole) }}
                                        </span>
                                    </td>
                                    <td>
                                        <button class="btn btn-sm btn-danger" @click="removeMember(member.id)">
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

        <!-- Monitors Dialog -->
        <div ref="monitorsDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("Monitors") }} - {{ currentGroup.name }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Add monitor form -->
                        <div class="row mb-3">
                            <div class="col-9">
                                <select v-model="addMonitorIDs" class="form-select" multiple size="5">
                                    <optgroup :label="$t('Monitoring Groups')">
                                        <option
                                            v-for="m in availableGroupMonitors"
                                            :key="m.id"
                                            :value="m.id"
                                        >
                                            &#128193; {{ m.name }}{{ m.permission_group_id ? ` (${$t('currentGroup', { group: getGroupName(m.permission_group_id) })})` : '' }}
                                        </option>
                                    </optgroup>
                                    <optgroup :label="$t('Individual Monitors')">
                                        <option
                                            v-for="m in availableIndividualMonitors"
                                            :key="m.id"
                                            :value="m.id"
                                        >
                                            {{ m.name }}{{ m.permission_group_id ? ` (${$t('currentGroup', { group: getGroupName(m.permission_group_id) })})` : '' }}
                                        </option>
                                    </optgroup>
                                </select>
                                <small class="text-muted">{{ $t("bulkSelectHint") }}</small>
                            </div>
                            <div class="col-3">
                                <button class="btn btn-primary w-100" :disabled="addMonitorIDs.length === 0" @click="addMonitorsToGroupBulk">
                                    <font-awesome-icon icon="plus" />
                                    {{ $t("Add") }} <span v-if="addMonitorIDs.length > 1">({{ addMonitorIDs.length }})</span>
                                </button>
                            </div>
                        </div>

                        <div v-if="groupMonitorList.length > 0" class="mb-2 text-muted">
                            <small>
                                <font-awesome-icon icon="info-circle" />
                                {{ $t("monitorGroupInheritanceNote") }}
                            </small>
                        </div>

                        <!-- Monitors list -->
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>{{ $t("Monitor") }}</th>
                                    <th>{{ $t("Type") }}</th>
                                    <th>{{ $t("Actions") }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-if="groupMonitorList.length === 0">
                                    <td colspan="3" class="text-center text-muted">
                                        {{ $t("No monitors assigned") }}
                                    </td>
                                </tr>
                                <tr v-for="m in groupMonitorList" :key="m.id">
                                    <td>
                                        <font-awesome-icon v-if="m.type === 'group'" icon="folder" class="me-1 text-warning" />
                                        {{ m.name }}
                                    </td>
                                    <td>
                                        <span v-if="m.type === 'group'" class="badge bg-warning text-dark">
                                            {{ $t("Monitoring Group") }}
                                        </span>
                                        <span v-else class="badge bg-secondary">
                                            {{ m.type }}
                                        </span>
                                    </td>
                                    <td>
                                        <button class="btn btn-sm btn-danger" @click="removeMonitorFromGroup(m.id)">
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
        <Confirm ref="confirmDelete" btn-style="btn-danger" :yes-text="$t('Yes')" :no-text="$t('No')" @yes="deleteGroup">
            {{ $t("deletePermissionGroupMsg") }}
        </Confirm>

        <!-- Quick Setup Wizard -->
        <div ref="wizardDialog" class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("quickSetupWizard") }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Step Indicator -->
                        <div class="wizard-steps mb-4">
                            <div v-for="s in 3" :key="s" class="wizard-step" :class="{ active: wizardStep === s, completed: wizardStep > s }">
                                <span class="step-number">{{ s }}</span>
                                <span class="step-label">{{ s === 1 ? $t("wizardStep1") : s === 2 ? $t("wizardStep2") : $t("wizardStep3") }}</span>
                            </div>
                        </div>

                        <!-- Step 1: Create Group -->
                        <div v-if="wizardStep === 1">
                            <h6>{{ $t("wizardStep1") }}</h6>
                            <div class="mb-3">
                                <label class="form-label">{{ $t("Name") }}</label>
                                <input v-model="wizardGroup.name" type="text" class="form-control" :placeholder="$t('wizardGroupNamePlaceholder')" />
                            </div>
                            <div class="mb-3">
                                <label class="form-label">{{ $t("Description") }}</label>
                                <textarea v-model="wizardGroup.description" class="form-control" rows="2"></textarea>
                            </div>
                        </div>

                        <!-- Step 2: Select Monitors -->
                        <div v-if="wizardStep === 2">
                            <h6>{{ $t("wizardStep2") }}</h6>
                            <select v-model="wizardMonitorIDs" class="form-select" multiple size="8">
                                <option v-for="m in allMonitors" :key="m.id" :value="m.id">
                                    {{ m.type === 'group' ? '📁 ' : '' }}{{ m.name }}
                                </option>
                            </select>
                            <small class="text-muted">{{ $t("bulkSelectHint") }}</small>
                        </div>

                        <!-- Step 3: Add Members -->
                        <div v-if="wizardStep === 3">
                            <h6>{{ $t("wizardStep3") }}</h6>
                            <div v-for="(member, idx) in wizardMembers" :key="idx" class="row mb-2">
                                <div class="col-6">
                                    <select v-model="member.userID" class="form-select">
                                        <option value="">{{ $t("Select User") }}</option>
                                        <option v-for="u in allUsers" :key="u.id" :value="u.id">
                                            {{ u.username }}
                                        </option>
                                    </select>
                                </div>
                                <div class="col-4">
                                    <select v-model="member.role" class="form-select">
                                        <option value="group-admin">{{ $t("Group Admin") }}</option>
                                        <option value="group-readonly">{{ $t("Group Read-Only") }}</option>
                                    </select>
                                </div>
                                <div class="col-2">
                                    <button class="btn btn-outline-danger btn-sm" @click="wizardMembers.splice(idx, 1)">
                                        <font-awesome-icon icon="trash" />
                                    </button>
                                </div>
                            </div>
                            <button class="btn btn-outline-primary btn-sm" @click="wizardMembers.push({ userID: '', role: 'group-readonly' })">
                                <font-awesome-icon icon="plus" /> {{ $t("addMember") }}
                            </button>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button v-if="wizardStep > 1" type="button" class="btn btn-secondary" @click="wizardStep--">
                            {{ $t("Back") }}
                        </button>
                        <button v-if="wizardStep < 3" type="button" class="btn btn-primary" :disabled="wizardStep === 1 && !wizardGroup.name" @click="wizardStep++">
                            {{ $t("Next") }}
                        </button>
                        <button v-if="wizardStep === 3" type="button" class="btn btn-success" :disabled="wizardProcessing" @click="runWizard">
                            <font-awesome-icon v-if="wizardProcessing" icon="spinner" spin />
                            {{ $t("wizardFinish") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
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
            groupList: [],
            allUsers: [],
            allMonitors: [],
            isEditing: false,
            dialogGroup: {
                name: "",
                description: "",
                active: true,
            },
            currentGroup: {},
            memberList: [],
            groupMonitorList: [],
            addMemberUserIDs: [],
            addMemberRole: "group-readonly",
            addMonitorIDs: [],
            deleteGroupID: null,
            wizardStep: 1,
            wizardGroup: { name: "", description: "" },
            wizardMonitorIDs: [],
            wizardMembers: [{ userID: "", role: "group-readonly" }],
            wizardProcessing: false,
        };
    },

    computed: {
        /**
         * Users not already in the current group
         * @returns {object[]} Available users
         */
        availableUsers() {
            const memberIDs = this.memberList.map(m => m.id);
            return this.allUsers.filter(u => !memberIDs.includes(u.id));
        },

        /**
         * Group-type monitors not already assigned to the current group
         * @returns {object[]} Available group monitors
         */
        availableGroupMonitors() {
            const assignedIDs = this.groupMonitorList.map(m => m.id);
            return this.allMonitors.filter(m => m.type === "group" && !assignedIDs.includes(m.id));
        },

        /**
         * Individual monitors not already assigned to the current group
         * @returns {object[]} Available individual monitors
         */
        availableIndividualMonitors() {
            const assignedIDs = this.groupMonitorList.map(m => m.id);
            return this.allMonitors.filter(m => m.type !== "group" && !assignedIDs.includes(m.id));
        },
    },

    mounted() {
        this.loadGroupList();
        this.loadAllUsers();
        this.loadAllMonitors();
    },

    methods: {
        /**
         * Load the list of permission groups
         * @returns {void}
         */
        loadGroupList() {
            this.$root.getSocket().emit("getPermissionGroupList", (res) => {
                if (res.ok) {
                    this.groupList = res.groups;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Load all users for member assignment
         * @returns {void}
         */
        loadAllUsers() {
            this.$root.getSocket().emit("getUserList", (res) => {
                if (res.ok) {
                    this.allUsers = res.users;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Load all monitors for monitor assignment
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
         * Get CSS class for role badge
         * @param {string} role Role name
         * @returns {string} CSS class
         */
        roleBadgeClass(role) {
            if (role === "full-admin") {
                return "bg-danger";
            }
            if (role === "group-admin") {
                return "bg-warning text-dark";
            }
            return "bg-info";
        },

        /**
         * Format role for display
         * @param {string} role Role name
         * @returns {string} Formatted role
         */
        formatRole(role) {
            const roleMap = {
                "full-admin": this.$t("Full Admin"),
                "group-admin": this.$t("Group Admin"),
                "group-readonly": this.$t("Group Read-Only"),
            };
            return roleMap[role] || role;
        },

        /**
         * Show add group dialog
         * @returns {void}
         */
        showAddDialog() {
            this.isEditing = false;
            this.dialogGroup = {
                name: "",
                description: "",
                active: true,
            };
            new Modal(this.$refs.groupDialog).show();
        },

        /**
         * Show edit group dialog
         * @param {object} group Group to edit
         * @returns {void}
         */
        showEditDialog(group) {
            this.isEditing = true;
            this.dialogGroup = {
                id: group.id,
                name: group.name,
                description: group.description || "",
                active: !!group.active,
            };
            new Modal(this.$refs.groupDialog).show();
        },

        /**
         * Show members dialog for a group
         * @param {object} group Group to manage members for
         * @returns {void}
         */
        showMembersDialog(group) {
            this.currentGroup = group;
            this.addMemberUserIDs = [];
            this.addMemberRole = "group-readonly";
            this.loadMembers(group.id);
            new Modal(this.$refs.membersDialog).show();
        },

        /**
         * Load members for a group
         * @param {number} groupID Group ID
         * @returns {void}
         */
        loadMembers(groupID) {
            this.$root.getSocket().emit("getPermissionGroupMembers", groupID, (res) => {
                if (res.ok) {
                    this.memberList = res.members;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Show delete group confirmation
         * @param {object} group Group to delete
         * @returns {void}
         */
        showDeleteDialog(group) {
            this.deleteGroupID = group.id;
            this.$refs.confirmDelete.show();
        },

        /**
         * Save group (add or edit)
         * @returns {void}
         */
        saveGroup() {
            if (this.isEditing) {
                this.$root.getSocket().emit("editPermissionGroup", this.dialogGroup, (res) => {
                    if (res.ok) {
                        this.$root.toastRes(res);
                        Modal.getInstance(this.$refs.groupDialog)?.hide();
                        this.loadGroupList();
                    } else {
                        this.$root.toastError(res.msg);
                    }
                });
            } else {
                this.$root.getSocket().emit("addPermissionGroup", this.dialogGroup, (res) => {
                    if (res.ok) {
                        this.$root.toastRes(res);
                        Modal.getInstance(this.$refs.groupDialog)?.hide();
                        this.loadGroupList();
                    } else {
                        this.$root.toastError(res.msg);
                    }
                });
            }
        },

        /**
         * Add members to the current group (supports bulk)
         * @returns {void}
         */
        addMembersBulk() {
            if (this.addMemberUserIDs.length === 0) {
                return;
            }
            let completed = 0;
            const total = this.addMemberUserIDs.length;
            for (const userID of this.addMemberUserIDs) {
                this.$root.getSocket().emit("addPermissionGroupMember", {
                    userID: parseInt(userID),
                    groupID: this.currentGroup.id,
                    role: this.addMemberRole,
                }, (res) => {
                    completed++;
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                    if (completed === total) {
                        this.$root.toastRes({ ok: true, msg: "successAdded", msgi18n: true });
                        this.loadMembers(this.currentGroup.id);
                        this.loadGroupList();
                        this.addMemberUserIDs = [];
                    }
                });
            }
        },

        /**
         * Remove a member from the current group
         * @param {number} userID User ID to remove
         * @returns {void}
         */
        removeMember(userID) {
            this.$root.getSocket().emit("removePermissionGroupMember", {
                userID,
                groupID: this.currentGroup.id,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadMembers(this.currentGroup.id);
                    this.loadGroupList();
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Show monitors dialog for a group
         * @param {object} group Group to manage monitors for
         * @returns {void}
         */
        showMonitorsDialog(group) {
            this.currentGroup = group;
            this.addMonitorIDs = [];
            this.loadGroupMonitors(group.id);
            this.loadAllMonitors();
            new Modal(this.$refs.monitorsDialog).show();
        },

        /**
         * Load monitors assigned to a group
         * @param {number} groupID Group ID
         * @returns {void}
         */
        loadGroupMonitors(groupID) {
            this.$root.getSocket().emit("getPermissionGroupMonitors", groupID, (res) => {
                if (res.ok) {
                    this.groupMonitorList = res.monitors;
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Get group name by group ID
         * @param {number} groupID Permission group ID
         * @returns {string} Group name or ID
         */
        getGroupName(groupID) {
            const group = this.groupList.find(g => g.id === groupID);
            return group ? group.name : `#${groupID}`;
        },

        /**
         * Add monitors to the current permission group (supports bulk)
         * @returns {void}
         */
        addMonitorsToGroupBulk() {
            if (this.addMonitorIDs.length === 0) {
                return;
            }
            // Check if any selected monitors are already in another group
            const movingMonitors = this.addMonitorIDs
                .map(id => this.allMonitors.find(m => m.id === parseInt(id)))
                .filter(m => m && m.permission_group_id && m.permission_group_id !== this.currentGroup.id);

            if (movingMonitors.length > 0) {
                if (!confirm(this.$t("moveMonitorConfirm", { fromGroup: this.getGroupName(movingMonitors[0].permission_group_id), toGroup: this.currentGroup.name }))) {
                    return;
                }
            }

            let completed = 0;
            const total = this.addMonitorIDs.length;
            for (const monitorID of this.addMonitorIDs) {
                this.$root.getSocket().emit("assignMonitorToPermissionGroup", {
                    monitorID: parseInt(monitorID),
                    groupID: this.currentGroup.id,
                }, (res) => {
                    completed++;
                    if (!res.ok) {
                        this.$root.toastError(res.msg);
                    }
                    if (completed === total) {
                        this.$root.toastRes({ ok: true, msg: "successAdded", msgi18n: true });
                        this.loadGroupMonitors(this.currentGroup.id);
                        this.loadGroupList();
                        this.loadAllMonitors();
                        this.addMonitorIDs = [];
                    }
                });
            }
        },

        /**
         * Remove a monitor from the current permission group
         * @param {number} monitorID Monitor ID
         * @returns {void}
         */
        removeMonitorFromGroup(monitorID) {
            this.$root.getSocket().emit("unassignMonitorFromPermissionGroup", {
                monitorID,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadGroupMonitors(this.currentGroup.id);
                    this.loadGroupList();
                } else {
                    this.$root.toastError(res.msg);
                }
            });
        },

        /**
         * Show the quick setup wizard dialog
         * @returns {void}
         */
        showWizard() {
            this.wizardStep = 1;
            this.wizardGroup = { name: "", description: "" };
            this.wizardMonitorIDs = [];
            this.wizardMembers = [{ userID: "", role: "group-readonly" }];
            this.wizardProcessing = false;
            this.loadAllMonitors();
            new Modal(this.$refs.wizardDialog).show();
        },

        /**
         * Run the wizard: create group, assign monitors, add members
         * @returns {void}
         */
        async runWizard() {
            this.wizardProcessing = true;
            try {
                // Step 1: Create the group
                const groupRes = await new Promise((resolve) => {
                    this.$root.getSocket().emit("addPermissionGroup", this.wizardGroup, resolve);
                });
                if (!groupRes.ok) {
                    this.$root.toastError(groupRes.msg);
                    this.wizardProcessing = false;
                    return;
                }
                const groupID = groupRes.group.id;

                // Step 2: Assign monitors
                for (const monitorID of this.wizardMonitorIDs) {
                    await new Promise((resolve) => {
                        this.$root.getSocket().emit("assignMonitorToPermissionGroup", {
                            monitorID: parseInt(monitorID),
                            groupID,
                        }, resolve);
                    });
                }

                // Step 3: Add members
                for (const member of this.wizardMembers) {
                    if (!member.userID) {
                        continue;
                    }
                    await new Promise((resolve) => {
                        this.$root.getSocket().emit("addPermissionGroupMember", {
                            userID: parseInt(member.userID),
                            groupID,
                            role: member.role,
                        }, resolve);
                    });
                }

                this.$root.toastRes({ ok: true, msg: "successAdded", msgi18n: true });
                Modal.getInstance(this.$refs.wizardDialog)?.hide();
                this.loadGroupList();
            } catch (e) {
                this.$root.toastError(e.message);
            } finally {
                this.wizardProcessing = false;
            }
        },

        /**
         * Delete a permission group
         * @returns {void}
         */
        deleteGroup() {
            this.$root.getSocket().emit("deletePermissionGroup", {
                id: this.deleteGroupID,
            }, (res) => {
                if (res.ok) {
                    this.$root.toastRes(res);
                    this.loadGroupList();
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
        .title {
            font-weight: bold;
        }

        .description {
            font-size: 0.9em;
        }
    }
}

.wizard-steps {
    display: flex;
    justify-content: center;
    gap: 30px;

    .wizard-step {
        display: flex;
        align-items: center;
        gap: 8px;
        opacity: 0.4;

        &.active {
            opacity: 1;
            font-weight: bold;
        }

        &.completed {
            opacity: 0.7;
        }

        .step-number {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background-color: $primary;
            color: white;
            font-size: 0.85em;
        }
    }
}
</style>
