export interface User {
    id: string;
    email?: string;
    phone?: string;
    username?: string;
    emailVerified: boolean;
    phoneVerified: boolean;
    metadata?: Record<string, any>;
    createdAt: string;
    updatedAt: string;
}

export interface AuthResponse {
    user: User;
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}

export interface LoginRequest {
    identifier: string; // email, username, or phone
    password: string;
}

export interface RegisterRequest {
    email?: string;
    phone?: string;
    username?: string;
    password: string;
}

export interface OTPRequest {
    recipient: string; // email or phone
    type: 'email' | 'sms';
    purpose: 'login' | 'registration' | 'verification';
}

export interface VerifyOTPRequest {
    recipient: string;
    code: string; // Changed from 'otp' to 'code' to match API
    type: 'email' | 'sms';
}

export interface RegisterOTPRequest {
    recipient: string;
    code: string;
    type: 'email' | 'sms';
    password?: string; // Optional for phone-only registration
}

export interface ResetPasswordRequest {
    identifier: string;
}

export interface ConfirmResetPasswordRequest {
    token: string;
    newPassword: string;
}

export class AuthError extends Error {
    constructor(
        message: string,
        public code: string,
        public status: number = 400
    ) {
        super(message);
        this.name = 'AuthError';
    }
}

// API client for authentication
export class AuthClient {
    private baseUrl: string;

    constructor(baseUrl: string = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080') {
        this.baseUrl = baseUrl;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const url = `${this.baseUrl}${endpoint}`;
        const token = this.getStoredToken();

        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(token && { Authorization: `Bearer ${token}` }),
                ...options.headers,
            },
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ message: 'Unknown error' }));
            throw new AuthError(error.message, error.code || 'UNKNOWN_ERROR', response.status);
        }

        return response.json();
    }

    async login(credentials: LoginRequest): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
        });

        this.storeTokens(response.accessToken, response.refreshToken);
        return response;
    }

    async register(userData: RegisterRequest): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData),
        });

        this.storeTokens(response.accessToken, response.refreshToken);
        return response;
    }

    async sendOTP(request: OTPRequest): Promise<void> {
        await this.request('/auth/otp/send', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async loginWithOTP(request: VerifyOTPRequest): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/otp/login', {
            method: 'POST',
            body: JSON.stringify(request),
        });

        this.storeTokens(response.accessToken, response.refreshToken);
        return response;
    }

    async registerWithOTP(request: RegisterOTPRequest): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/otp/register', {
            method: 'POST',
            body: JSON.stringify(request),
        });

        this.storeTokens(response.accessToken, response.refreshToken);
        return response;
    }

    async verifyOTP(request: VerifyOTPRequest): Promise<void> {
        await this.request('/auth/otp/verify', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async resetPassword(request: ResetPasswordRequest): Promise<void> {
        await this.request('/auth/password/reset', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async confirmResetPassword(request: ConfirmResetPasswordRequest): Promise<void> {
        await this.request('/auth/password/confirm', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async refreshToken(): Promise<AuthResponse> {
        const refreshToken = this.getStoredRefreshToken();
        if (!refreshToken) {
            throw new AuthError('No refresh token available', 'NO_REFRESH_TOKEN', 401);
        }

        const response = await this.request<AuthResponse>('/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refreshToken }),
        });

        this.storeTokens(response.accessToken, response.refreshToken);
        return response;
    }

    async getCurrentUser(): Promise<User> {
        return this.request<User>('/auth/me');
    }

    async logout(): Promise<void> {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } finally {
            this.clearTokens();
        }
    }

    private storeTokens(accessToken: string, refreshToken: string): void {
        if (typeof window !== 'undefined') {
            localStorage.setItem('accessToken', accessToken);
            localStorage.setItem('refreshToken', refreshToken);
        }
    }

    private getStoredToken(): string | null {
        if (typeof window !== 'undefined') {
            return localStorage.getItem('accessToken');
        }
        return null;
    }

    private getStoredRefreshToken(): string | null {
        if (typeof window !== 'undefined') {
            return localStorage.getItem('refreshToken');
        }
        return null;
    }

    private clearTokens(): void {
        if (typeof window !== 'undefined') {
            localStorage.removeItem('accessToken');
            localStorage.removeItem('refreshToken');
        }
    }

    isAuthenticated(): boolean {
        return !!this.getStoredToken();
    }
}

export const authClient = new AuthClient();