// Type definitions for the admin dashboard

export interface User {
	id: string;
	email?: string;
	phone?: string;
	username?: string;
	email_verified: boolean;
	phone_verified: boolean;
	admin_level?: AdminLevel;
	capabilities?: AdminCapabilities;
	assigned_tables: string[];
	mfa_enabled: boolean;
	last_login?: string;
	failed_attempts: number;
	locked_until?: string;
	metadata: Record<string, any>;
	created_at: string;
	updated_at: string;
	created_by?: string;
	updated_by?: string;
}

export type AdminLevel = 'system_admin' | 'super_admin' | 'regular_admin' | 'moderator';

export interface AdminCapabilities {
	// System-level capabilities (System Admin only)
	can_access_sql: boolean;
	can_manage_database: boolean;
	can_manage_system: boolean;
	can_create_super_admin: boolean;
	can_install_plugins: boolean;
	can_modify_security_config: boolean;

	// Super admin capabilities
	can_create_admins: boolean;
	can_manage_all_tables: boolean;
	can_manage_auth: boolean;
	can_manage_storage: boolean;
	can_view_all_logs: boolean;
	can_manage_templates: boolean;
	can_manage_cron_jobs: boolean;

	// Regular admin capabilities
	can_manage_users: boolean;
	can_manage_content: boolean;
	assigned_tables: string[];
	assigned_user_groups: string[];
	can_export_data: boolean;

	// Moderator capabilities
	can_view_reports: boolean;
	can_moderate_content: boolean;
	can_view_basic_logs: boolean;

	// Common capabilities
	can_view_dashboard: boolean;
	can_update_profile: boolean;
}

export interface AdminSession {
	id: string;
	user_id: string;
	session_token: string;
	refresh_token?: string;
	ip_address?: string;
	user_agent?: string;
	expires_at: string;
	created_at: string;
	last_activity: string;
}

export interface Template {
	id: string;
	type: 'email' | 'sms';
	purpose: string;
	language: string;
	subject?: string;
	content: string;
	variables: TemplateVariable[];
	is_default: boolean;
	is_active: boolean;
	created_by: string;
	created_at: string;
	updated_by: string;
	updated_at: string;
}

export interface TemplateVariable {
	name: string;
	description: string;
	type: string;
	required: boolean;
	example: string;
}

export interface UserFilter {
	search?: string;
	admin_level?: AdminLevel;
	verified?: boolean;
	limit?: number;
	offset?: number;
}

export interface AdminFilter {
	search?: string;
	level?: AdminLevel;
	limit?: number;
	offset?: number;
}

export interface TemplateFilter {
	type?: 'email' | 'sms';
	purpose?: string;
	language?: string;
	is_active?: boolean;
	limit?: number;
	offset?: number;
}

export interface CreateUserRequest {
	email?: string;
	phone?: string;
	username?: string;
	password: string;
	admin_level?: AdminLevel;
	assigned_tables?: string[];
}

export interface UpdateUserRequest {
	email?: string;
	phone?: string;
	username?: string;
	metadata?: Record<string, any>;
}

export interface PromoteUserRequest {
	admin_level: AdminLevel;
	reason?: string;
	assigned_tables?: string[];
}

export interface CreateTemplateRequest {
	type: 'email' | 'sms';
	purpose: string;
	language: string;
	subject?: string;
	content: string;
	variables?: TemplateVariable[];
	is_default?: boolean;
	is_active?: boolean;
}

export interface UpdateTemplateRequest {
	subject?: string;
	content?: string;
	variables?: TemplateVariable[];
	is_active?: boolean;
}

export interface MFASetupRequest {
	method: 'totp' | 'backup_codes';
}

export interface MFAVerifyRequest {
	code: string;
}

export interface AuthConfig {
	jwt_secret: string;
	access_token_expiration: string;
	refresh_token_expiration: string;
	enable_cookie_auth: boolean;
	cookie_http_only: boolean;
	cookie_secure: boolean;
	cookie_same_site: string;
	mfa_required_for_admins: boolean;
	password_min_length: number;
	password_require_uppercase: boolean;
	password_require_lowercase: boolean;
	password_require_numbers: boolean;
	password_require_symbols: boolean;
	max_failed_attempts: number;
	lockout_duration: string;
}

export interface APIResponse<T = any> {
	message: string;
	data?: T;
	error?: string;
}

export interface PaginatedResponse<T = any> {
	data: T[];
	total: number;
	limit: number;
	offset: number;
}