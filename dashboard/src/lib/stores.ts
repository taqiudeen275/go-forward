// Svelte stores for state management

import { writable, derived } from 'svelte/store';
import type { User, AdminSession } from './types';

// Authentication state
export const currentUser = writable<User | null>(null);
export const currentSession = writable<AdminSession | null>(null);
export const isAuthenticated = derived(currentUser, ($user) => $user !== null);
export const isAdmin = derived(currentUser, ($user) => $user?.admin_level !== undefined);

// UI state
export const sidebarOpen = writable(false);
export const theme = writable<'light' | 'dark'>('light');
export const loading = writable(false);
export const notifications = writable<Array<{ id: string; type: 'success' | 'error' | 'warning' | 'info'; message: string; timeout?: number }>>([]);

// Data stores
export const users = writable<User[]>([]);
export const admins = writable<User[]>([]);
export const sessions = writable<AdminSession[]>([]);
export const templates = writable<any[]>([]);

// Utility functions for notifications
export function addNotification(type: 'success' | 'error' | 'warning' | 'info', message: string, timeout = 5000) {
	const id = Math.random().toString(36).substr(2, 9);
	notifications.update(items => [...items, { id, type, message, timeout }]);
	
	if (timeout > 0) {
		setTimeout(() => {
			removeNotification(id);
		}, timeout);
	}
}

export function removeNotification(id: string) {
	notifications.update(items => items.filter(item => item.id !== id));
}

// Theme management
export function toggleTheme() {
	theme.update(current => current === 'light' ? 'dark' : 'light');
}

// Initialize theme from localStorage
if (typeof window !== 'undefined') {
	const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null;
	if (savedTheme) {
		theme.set(savedTheme);
	}
	
	// Save theme changes to localStorage
	theme.subscribe(value => {
		localStorage.setItem('theme', value);
		document.documentElement.classList.toggle('dark', value === 'dark');
	});
}