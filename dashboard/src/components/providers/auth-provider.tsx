'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import { User, AuthResponse, authClient, AuthError } from '@/lib/auth';

interface AuthContextType {
    user: User | null;
    loading: boolean;
    error: string | null;
    login: (identifier: string, password: string) => Promise<void>;
    register: (email?: string, phone?: string, username?: string, password?: string) => Promise<void>;
    sendOTP: (identifier: string, type: 'email' | 'sms', purpose: 'login' | 'registration' | 'verification') => Promise<void>;
    loginWithOTP: (identifier: string, code: string, type: 'email' | 'sms') => Promise<void>;
    registerWithOTP: (identifier: string, code: string, type: 'email' | 'sms', password?: string) => Promise<void>;
    verifyOTP: (identifier: string, code: string, type: 'email' | 'sms') => Promise<void>;
    resetPassword: (identifier: string) => Promise<void>;
    confirmResetPassword: (token: string, newPassword: string) => Promise<void>;
    logout: () => Promise<void>;
    clearError: () => void;
    isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

interface AuthProviderProps {
    children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const clearError = () => setError(null);

    const handleAuthResponse = (response: AuthResponse) => {
        setUser(response.user);
        setError(null);
    };

    const handleError = (err: unknown) => {
        if (err instanceof AuthError) {
            setError(err.message);
        } else if (err instanceof Error) {
            setError(err.message);
        } else {
            setError('An unexpected error occurred');
        }
    };

    const login = async (identifier: string, password: string) => {
        try {
            setLoading(true);
            setError(null);
            const response = await authClient.login({ identifier, password });
            handleAuthResponse(response);
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const register = async (
        email?: string,
        phone?: string,
        username?: string,
        password?: string
    ) => {
        try {
            setLoading(true);
            setError(null);
            const response = await authClient.register({
                email,
                phone,
                username,
                password: password || '',
            });
            handleAuthResponse(response);
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const sendOTP = async (identifier: string, type: 'email' | 'sms', purpose: 'login' | 'registration' | 'verification') => {
        try {
            setLoading(true);
            setError(null);
            await authClient.sendOTP({ recipient: identifier, type, purpose });
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const loginWithOTP = async (identifier: string, code: string, type: 'email' | 'sms') => {
        try {
            setLoading(true);
            setError(null);
            const response = await authClient.loginWithOTP({ recipient: identifier, code, type });
            handleAuthResponse(response);
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const registerWithOTP = async (identifier: string, code: string, type: 'email' | 'sms', password?: string) => {
        try {
            setLoading(true);
            setError(null);
            const response = await authClient.registerWithOTP({ recipient: identifier, code, type, password });
            handleAuthResponse(response);
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const verifyOTP = async (identifier: string, code: string, type: 'email' | 'sms') => {
        try {
            setLoading(true);
            setError(null);
            await authClient.verifyOTP({ recipient: identifier, code, type });
            // For verification, we don't get auth response, just success
            // Optionally refresh user data to update verification status
            if (user) {
                const updatedUser = await authClient.getCurrentUser();
                setUser(updatedUser);
            }
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const resetPassword = async (identifier: string) => {
        try {
            setLoading(true);
            setError(null);
            await authClient.resetPassword({ identifier });
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const confirmResetPassword = async (token: string, newPassword: string) => {
        try {
            setLoading(true);
            setError(null);
            await authClient.confirmResetPassword({ token, newPassword });
        } catch (err) {
            handleError(err);
            throw err;
        } finally {
            setLoading(false);
        }
    };

    const logout = async () => {
        try {
            setLoading(true);
            await authClient.logout();
            setUser(null);
            setError(null);
        } catch (err) {
            handleError(err);
        } finally {
            setLoading(false);
        }
    };

    // Initialize auth state on mount
    useEffect(() => {
        const initializeAuth = async () => {
            try {
                if (authClient.isAuthenticated()) {
                    const currentUser = await authClient.getCurrentUser();
                    setUser(currentUser);
                }
            } catch (err) {
                // Token might be expired, try to refresh
                try {
                    const response = await authClient.refreshToken();
                    handleAuthResponse(response);
                } catch (refreshErr) {
                    // Refresh failed, clear tokens
                    await authClient.logout();
                    setUser(null);
                }
            } finally {
                setLoading(false);
            }
        };

        initializeAuth();
    }, []);

    const value: AuthContextType = {
        user,
        loading,
        error,
        login,
        register,
        sendOTP,
        loginWithOTP,
        registerWithOTP,
        verifyOTP,
        resetPassword,
        confirmResetPassword,
        logout,
        clearError,
        isAuthenticated: !!user,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}