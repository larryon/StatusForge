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
                    </div>
                </div>

                <div class="buttons">
                    <div class="btn-group" role="group">
                        <button class="btn btn-normal" @click="showEditDialog(user)">
                            <font-awesome-icon icon="edit" />
                            {{ $t("Edit") }}
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
                                <option value="admin">{{ $t("Admin") }}</option>
                                <option value="read-only">{{ $t("Read-Only") }}</option>
                            </select>
                            <div v-if="isEditing && dialogUser.id === currentUserID" class="form-text text-warning">
                                {{ $t("cannotChangeOwnRole") }}
                            </div>
                            <div class="form-text">
                                <strong>{{ $t("Admin") }}</strong>: {{ $t("roleDescAdmin") }}<br>
                                <strong>{{ $t("Read-Only") }}</strong>: {{ $t("roleDescReadOnly") }}
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
            isEditing: false,
            dialogUser: {
                username: "",
                password: "",
                role: "read-only",
                active: true,
            },
            resetPasswordUser: {},
            newPassword: "",
            deleteUserID: null,
            currentUserID: null,
        };
    },

    mounted() {
        this.loadUserList();
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
            if (role === "admin") {
                return "bg-danger";
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
                "admin": this.$t("Admin"),
                "read-only": this.$t("Read-Only"),
            };
            return roleMap[role] || role;
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
                role: "read-only",
                active: true,
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
                        Modal.getInstance(this.$refs.userDialog)?.hide();
                        this.loadUserList();
                    } else {
                        this.$root.toastError(res.msg);
                    }
                });
            }
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
</style>
