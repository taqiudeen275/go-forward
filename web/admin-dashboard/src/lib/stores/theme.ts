import { writable, derived } from 'svelte/store';
import { browser } from '$app/environment';

// Theme types
export type ThemeMode = 'light' | 'dark' | 'system';
export type AdminRole = 'system-admin' | 'super-admin' | 'regular-admin' | 'moderator';

// Theme configuration
export interface ThemeConfig {
	mode: ThemeMode;
	role: AdminRole;
	autoSwitch: boolean;
}

// Default theme configuration
const defaultTheme: ThemeConfig = {
	mode: 'system',
	role: 'regular-admin',
	autoSwitch: true
};

// Get initial theme from localStorage or default
function getInitialTheme(): ThemeConfig {
	if (!browser) return defaultTheme;
	
	try {
		const stored = localStorage.getItem('admin-theme');
		if (stored) {
			return { ...defaultTheme, ...JSON.parse(stored) };
		}
	} catch (e) {
		console.warn('Failed to parse stored theme:', e);
	}
	
	return defaultTheme;
}

// Create theme store
export const themeConfig = writable<ThemeConfig>(getInitialTheme());

// Derived store for computed theme values
export const theme = derived(themeConfig, ($config) => {
	let actualMode: 'light' | 'dark' = $config.mode === 'system' 
		? (browser && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
		: $config.mode;
	
	return {
		mode: actualMode,
		role: $config.role,
		autoSwitch: $config.autoSwitch,
		isDark: actualMode === 'dark',
		isLight: actualMode === 'light',
		themeClass: `theme-${$config.role}`,
		modeClass: actualMode
	};
});

// Theme actions
export const themeActions = {
	setMode: (mode: ThemeMode) => {
		themeConfig.update(config => ({ ...config, mode }));
	},
	
	setRole: (role: AdminRole) => {
		themeConfig.update(config => ({ ...config, role }));
	},
	
	toggleMode: () => {
		themeConfig.update(config => ({
			...config,
			mode: config.mode === 'light' ? 'dark' : config.mode === 'dark' ? 'system' : 'light'
		}));
	},
	
	toggleAutoSwitch: () => {
		themeConfig.update(config => ({ ...config, autoSwitch: !config.autoSwitch }));
	},
	
	reset: () => {
		themeConfig.set(defaultTheme);
	}
};

// Persist theme to localStorage
if (browser) {
	themeConfig.subscribe(config => {
		try {
			localStorage.setItem('admin-theme', JSON.stringify(config));
		} catch (e) {
			console.warn('Failed to save theme to localStorage:', e);
		}
	});
	
	// Listen for system theme changes
	const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
	mediaQuery.addEventListener('change', () => {
		// Trigger reactivity for system theme
		themeConfig.update(config => ({ ...config }));
	});
}

// Role-based theme colors and properties
export const roleThemes = {
	'system-admin': {
		name: 'System Administrator',
		color: 'purple',
		description: 'Full system access with advanced controls',
		icon: '🔧'
	},
	'super-admin': {
		name: 'Super Administrator', 
		color: 'blue',
		description: 'Business-level administrative access',
		icon: '👑'
	},
	'regular-admin': {
		name: 'Administrator',
		color: 'green', 
		description: 'Standard administrative access',
		icon: '⚙️'
	},
	'moderator': {
		name: 'Moderator',
		color: 'amber',
		description: 'Content moderation and basic access',
		icon: '🛡️'
	}
} as const;