// API client for the admin dashboard

import type {
	User,
	AdminSession,
	Template,
	UserFilter,
	AdminFilter,
	TemplateFilter,
	CreateUserRequest,
	UpdateUserRequest,
	PromoteUserRequest,
	CreateTemplateRequest,
	UpdateTemplateRequest,
	MFASetupRequest,
	MFAVerifyRequest,
	AuthConfig,
	APIResponse,
	PaginatedResponse
} from './types';

const API_BASE = '/api';

class APIClient {
	private async request<T>(
		endpoint: string,
		options: RequestInit = {}
	): Promise<APIResponse<T>> {
		const url = `${API_BASE}${endpoint}`;
		const response = await fetch(url, {
			headers: {
				'Content-Type': 'application/json',
				...options.headers
			},
			credentials: 'include', // Include cookies for authentication
			...options
		});

		if (!response.ok) {
			const error = await response.json().catch(() => ({ error: 'Network error' }));
			throw new Error(error.error || error.message || 'Request failed');
		}

		return response.json();
	}

	// Authentication endpoints
	async login(identifier: string, password: string): Promise<APIResponse<{ user: User; access_token: string }>> {
		return this.request('/auth/login', {
			method: 'POST',
			body: JSON.stringify({ identifier, password })
		});
	}

	async adminLogin(identifier: string, password: string, mfa_code?: string): Promise<APIResponse<{ user: User; session: AdminSession }>> {
		return this.request('/admin/auth/login', {
			method: 'POST',
			body: JSON.stringify({ identifier, password, mfa_code })
		});
	}

	async logout(): Promise<APIResponse> {
		return this.request('/auth/logout', { method: 'POST' });
	}

	async adminLogout(): Promise<APIResponse> {
		return this.request('/admin/auth/logout', { method: 'POST' });
	}

	async getCurrentUser(): Promise<APIResponse<User>> {
		return this.request('/auth/me');
	}

	async getAdminSession(): Promise<APIResponse<{ user: User; session: AdminSession }>> {
		return this.request('/admin/auth/session');
	}

	// User management endpoints
	async listUsers(filter: UserFilter = {}): Promise<APIResponse<PaginatedResponse<User>>> {
		const params = new URLSearchParams();
		Object.entries(filter).forEach(([key, value]) => {
			if (value !== undefined) {
				params.append(key, String(value));
			}
		});
		
		return this.request(`/admin/users?${params}`);
	}

	async getUser(id: string): Promise<APIResponse<User>> {
		return this.request(`/admin/users/${id}`);
	}

	async createUser(data: CreateUserRequest): Promise<APIResponse<User>> {
		return this.request('/admin/users', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async updateUser(id: string, data: UpdateUserRequest): Promise<APIResponse<User>> {
		return this.request(`/admin/users/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async deleteUser(id: string): Promise<APIResponse> {
		return this.request(`/admin/users/${id}`, { method: 'DELETE' });
	}

	async promoteUser(id: string, data: PromoteUserRequest): Promise<APIResponse> {
		return this.request(`/admin/users/${id}/promote`, {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async demoteUser(id: string, reason?: string): Promise<APIResponse> {
		return this.request(`/admin/users/${id}/demote`, {
			method: 'POST',
			body: JSON.stringify({ reason })
		});
	}

	async lockUser(id: string, reason: string): Promise<APIResponse> {
		return this.request(`/admin/users/${id}/lock`, {
			method: 'POST',
			body: JSON.stringify({ reason })
		});
	}

	async unlockUser(id: string): Promise<APIResponse> {
		return this.request(`/admin/users/${id}/unlock`, { method: 'POST' });
	}

	// Admin management endpoints
	async listAdmins(filter: AdminFilter = {}): Promise<APIResponse<PaginatedResponse<User>>> {
		const params = new URLSearchParams();
		Object.entries(filter).forEach(([key, value]) => {
			if (value !== undefined) {
				params.append(key, String(value));
			}
		});
		
		return this.request(`/admin/admins?${params}`);
	}

	async getAdminSessions(id: string): Promise<APIResponse<AdminSession[]>> {
		return this.request(`/admin/admins/${id}/sessions`);
	}

	async revokeAdminSessions(id: string): Promise<APIResponse> {
		return this.request(`/admin/admins/${id}/sessions`, { method: 'DELETE' });
	}

	// MFA endpoints
	async setupMFA(method: 'totp' | 'backup_codes'): Promise<APIResponse<{ secret?: string; qr_code?: string; backup_codes?: string[] }>> {
		return this.request('/auth/mfa/setup', {
			method: 'POST',
			body: JSON.stringify({ method })
		});
	}

	async verifyMFA(code: string): Promise<APIResponse> {
		return this.request('/auth/mfa/verify', {
			method: 'POST',
			body: JSON.stringify({ code })
		});
	}

	async disableMFA(): Promise<APIResponse> {
		return this.request('/auth/mfa/disable', { method: 'POST' });
	}

	async generateBackupCodes(): Promise<APIResponse<{ backup_codes: string[] }>> {
		return this.request('/auth/mfa/backup-codes', { method: 'POST' });
	}

	// Template management endpoints
	async listTemplates(filter: TemplateFilter = {}): Promise<APIResponse<PaginatedResponse<Template>>> {
		const params = new URLSearchParams();
		Object.entries(filter).forEach(([key, value]) => {
			if (value !== undefined) {
				params.append(key, String(value));
			}
		});
		
		return this.request(`/admin/templates?${params}`);
	}

	async getTemplate(id: string): Promise<APIResponse<Template>> {
		return this.request(`/admin/templates/${id}`);
	}

	async createTemplate(data: CreateTemplateRequest): Promise<APIResponse<Template>> {
		return this.request('/admin/templates', {
			method: 'POST',
			body: JSON.stringify(data)
		});
	}

	async updateTemplate(id: string, data: UpdateTemplateRequest): Promise<APIResponse<Template>> {
		return this.request(`/admin/templates/${id}`, {
			method: 'PUT',
			body: JSON.stringify(data)
		});
	}

	async deleteTemplate(id: string): Promise<APIResponse> {
		return this.request(`/admin/templates/${id}`, { method: 'DELETE' });
	}

	async previewTemplate(templateId: string, variables: Record<string, any>): Promise<APIResponse<{ rendered_content: string; rendered_subject?: string }>> {
		return this.request(`/admin/templates/${templateId}/preview`, {
			method: 'POST',
			body: JSON.stringify({ variables })
		});
	}

	async getTemplateVariables(purpose: string): Promise<APIResponse<{ variables: any[] }>> {
		return this.request(`/admin/templates/variables/${purpose}`);
	}

	// Authentication configuration endpoints
	async getAuthConfig(): Promise<APIResponse<AuthConfig>> {
		return this.request('/admin/config/auth');
	}

	async updateAuthConfig(config: Partial<AuthConfig>): Promise<APIResponse<AuthConfig>> {
		return this.request('/admin/config/auth', {
			method: 'PUT',
			body: JSON.stringify(config)
		});
	}

	// Session management endpoints
	async listSessions(): Promise<APIResponse<AdminSession[]>> {
		return this.request('/admin/sessions');
	}

	async revokeSession(sessionId: string): Promise<APIResponse> {
		return this.request(`/admin/sessions/${sessionId}`, { method: 'DELETE' });
	}

	async revokeAllSessions(): Promise<APIResponse> {
		return this.request('/admin/sessions', { method: 'DELETE' });
	}
}

export const api = new APIClient();