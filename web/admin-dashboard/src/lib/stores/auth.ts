import { writable, derived } from 'svelte/store';
import { browser } from '$app/environment';
import type { AdminRole } from './theme';

// Authentication types
export interface AdminUser {
	id: string;
	email: string;
	name: string;
	role: AdminRole;
	mfaEnabled: boolean;
	lastLogin?: Date;
	avatar?: string;
}

export interface AuthSession {
	user: AdminUser;
	token: string;
	expiresAt: Date;
	mfaVerified: boolean;
	sessionId: string;
}

export interface LoginCredentials {
	email: string;
	password: string;
	rememberMe?: boolean;
}

export interface MFAVerification {
	code: string;
	backupCode?: boolean;
}

// Auth state
interface AuthState {
	session: AuthSession | null;
	loading: boolean;
	error: string | null;
	mfaPending: boolean;
	csrfToken: string | null;
}

const initialState: AuthState = {
	session: null,
	loading: false,
	error: null,
	mfaPending: false,
	csrfToken: null
};

// Create auth store
export const authState = writable<AuthState>(initialState);

// Derived stores for convenience
export const isAuthenticated = derived(authState, ($auth) => !!$auth.session);
export const currentUser = derived(authState, ($auth) => $auth.session?.user || null);
export const isLoading = derived(authState, ($auth) => $auth.loading);
export const authError = derived(authState, ($auth) => $auth.error);
export const isMFAPending = derived(authState, ($auth) => $auth.mfaPending);

// Auth API functions
class AuthAPI {
	private baseURL = '/api/admin/auth';

	// Get CSRF token
	async getCSRFToken(): Promise<string> {
		const response = await fetch(`${this.baseURL}/csrf`, {
			method: 'GET',
			credentials: 'include'
		});
		
		if (!response.ok) {
			throw new Error('Failed to get CSRF token');
		}
		
		const data = await response.json();
		return data.token;
	}

	// Login with credentials
	async login(credentials: LoginCredentials, csrfToken: string): Promise<{ requiresMFA: boolean; session?: AuthSession }> {
		const response = await fetch(`${this.baseURL}/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-CSRF-Token': csrfToken
			},
			credentials: 'include',
			body: JSON.stringify(credentials)
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.message || 'Login failed');
		}

		return await response.json();
	}

	// Verify MFA
	async verifyMFA(verification: MFAVerification, csrfToken: string): Promise<AuthSession> {
		const response = await fetch(`${this.baseURL}/mfa/verify`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-CSRF-Token': csrfToken
			},
			credentials: 'include',
			body: JSON.stringify(verification)
		});

		if (!response.ok) {
			const error = await response.json();
			throw new Error(error.message || 'MFA verification failed');
		}

		return await response.json();
	}

	// Check current session
	async checkSession(): Promise<AuthSession | null> {
		try {
			const response = await fetch(`${this.baseURL}/session`, {
				method: 'GET',
				credentials: 'include'
			});

			if (!response.ok) {
				return null;
			}

			return await response.json();
		} catch {
			return null;
		}
	}

	// Logout
	async logout(csrfToken: string): Promise<void> {
		await fetch(`${this.baseURL}/logout`, {
			method: 'POST',
			headers: {
				'X-CSRF-Token': csrfToken
			},
			credentials: 'include'
		});
	}

	// Refresh session
	async refreshSession(): Promise<AuthSession> {
		const response = await fetch(`${this.baseURL}/refresh`, {
			method: 'POST',
			credentials: 'include'
		});

		if (!response.ok) {
			throw new Error('Session refresh failed');
		}

		return await response.json();
	}
}

const authAPI = new AuthAPI();

// Auth actions
export const authActions = {
	// Initialize auth (check existing session)
	async init() {
		if (!browser) return;

		authState.update(state => ({ ...state, loading: true }));

		try {
			// Get CSRF token
			const csrfToken = await authAPI.getCSRFToken();
			
			// Check existing session
			const session = await authAPI.checkSession();

			authState.update(state => ({
				...state,
				session,
				csrfToken,
				loading: false,
				error: null
			}));
		} catch (error) {
			authState.update(state => ({
				...state,
				loading: false,
				error: error instanceof Error ? error.message : 'Authentication check failed'
			}));
		}
	},

	// Login
	async login(credentials: LoginCredentials) {
		authState.update(state => ({ ...state, loading: true, error: null }));

		try {
			const { csrfToken } = authState.get();
			if (!csrfToken) {
				throw new Error('CSRF token not available');
			}

			const result = await authAPI.login(credentials, csrfToken);

			if (result.requiresMFA) {
				authState.update(state => ({
					...state,
					loading: false,
					mfaPending: true
				}));
			} else if (result.session) {
				authState.update(state => ({
					...state,
					session: result.session!,
					loading: false,
					mfaPending: false
				}));
			}
		} catch (error) {
			authState.update(state => ({
				...state,
				loading: false,
				error: error instanceof Error ? error.message : 'Login failed'
			}));
		}
	},

	// Verify MFA
	async verifyMFA(verification: MFAVerification) {
		authState.update(state => ({ ...state, loading: true, error: null }));

		try {
			const { csrfToken } = authState.get();
			if (!csrfToken) {
				throw new Error('CSRF token not available');
			}

			const session = await authAPI.verifyMFA(verification, csrfToken);

			authState.update(state => ({
				...state,
				session,
				loading: false,
				mfaPending: false
			}));
		} catch (error) {
			authState.update(state => ({
				...state,
				loading: false,
				error: error instanceof Error ? error.message : 'MFA verification failed'
			}));
		}
	},

	// Logout
	async logout() {
		authState.update(state => ({ ...state, loading: true }));

		try {
			const { csrfToken } = authState.get();
			if (csrfToken) {
				await authAPI.logout(csrfToken);
			}
		} catch (error) {
			console.warn('Logout request failed:', error);
		} finally {
			// Clear state regardless of API call success
			authState.set(initialState);
		}
	},

	// Clear error
	clearError() {
		authState.update(state => ({ ...state, error: null }));
	},

	// Refresh session
	async refreshSession() {
		try {
			const session = await authAPI.refreshSession();
			authState.update(state => ({ ...state, session }));
		} catch (error) {
			// If refresh fails, clear session
			authState.update(state => ({ ...state, session: null }));
			throw error;
		}
	}
};

// Auto-refresh session before expiry
if (browser) {
	let refreshTimer: NodeJS.Timeout;

	authState.subscribe(($auth) => {
		if (refreshTimer) {
			clearTimeout(refreshTimer);
		}

		if ($auth.session) {
			const expiresAt = new Date($auth.session.expiresAt);
			const now = new Date();
			const timeUntilExpiry = expiresAt.getTime() - now.getTime();
			
			// Refresh 5 minutes before expiry
			const refreshTime = Math.max(timeUntilExpiry - 5 * 60 * 1000, 60 * 1000);

			if (refreshTime > 0) {
				refreshTimer = setTimeout(() => {
					authActions.refreshSession().catch(() => {
						// If refresh fails, user will be logged out
					});
				}, refreshTime);
			}
		}
	});
}