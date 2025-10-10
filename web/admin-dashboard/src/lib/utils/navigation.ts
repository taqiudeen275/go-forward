import { goto as svelteGoto } from '$app/navigation';
import { base } from '$app/paths';

/**
 * Navigate to a path with proper base path handling
 */
export function goto(path: string, options?: Parameters<typeof svelteGoto>[1]) {
	// Ensure path starts with /
	const normalizedPath = path.startsWith('/') ? path : `/${path}`;
	
	// Combine base path with the target path
	const fullPath = `${base}${normalizedPath}`;
	
	return svelteGoto(fullPath, options);
}

/**
 * Get the full URL for a path with base path
 */
export function getPath(path: string): string {
	const normalizedPath = path.startsWith('/') ? path : `/${path}`;
	return `${base}${normalizedPath}`;
}

/**
 * Check if current path matches (accounting for base path)
 */
export function isCurrentPath(path: string, currentPath: string): boolean {
	const normalizedPath = path.startsWith('/') ? path : `/${path}`;
	const fullPath = `${base}${normalizedPath}`;
	return currentPath === fullPath || currentPath.startsWith(fullPath + '/');
}