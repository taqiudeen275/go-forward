<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$lib/utils/navigation';
	import { page } from '$app/stores';
	import { authActions, isAuthenticated, isLoading, currentUser } from '$lib/stores/auth';
	import type { AdminRole } from '$lib/stores/theme';
	
	interface Props {
		requiredRole?: AdminRole;
		redirectTo?: string;
		children?: any;
	}
	
	let { requiredRole, redirectTo = '/login', children }: Props = $props();
	
	// Public routes that don't require authentication
	const publicRoutes = ['/login', '/login/mfa', '/login/forgot-password'];
	
	// Check if current route is public (using route ID to avoid base path issues)
	const isPublicRoute = $derived(publicRoutes.some(route => $page.route.id?.startsWith(route)));
	
	// Check if user has required role
	const hasRequiredRole = $derived(() => {
		if (!requiredRole || !$currentUser) return true;
		
		const roleHierarchy: Record<AdminRole, number> = {
			'moderator': 1,
			'regular-admin': 2,
			'super-admin': 3,
			'system-admin': 4
		};
		
		const userLevel = roleHierarchy[$currentUser.role] || 0;
		const requiredLevel = roleHierarchy[requiredRole] || 0;
		
		return userLevel >= requiredLevel;
	});
	
	onMount(() => {
		// Initialize auth on app start
		authActions.init();
	});
	
	// Handle authentication redirects
	$effect(() => {
		if ($isLoading) return; // Wait for auth check to complete
		
		const currentPath = $page.url.pathname;
		
		if (!$isAuthenticated && !isPublicRoute) {
			// Redirect to login if not authenticated and not on public route
			goto(`/login?redirect=${encodeURIComponent(currentPath)}`);
		} else if ($isAuthenticated && isPublicRoute) {
			// Redirect to dashboard if authenticated and on public route
			const redirect = $page.url.searchParams.get('redirect');
			goto(redirect || '/');
		} else if ($isAuthenticated && requiredRole && !hasRequiredRole()) {
			// Redirect if user doesn't have required role
			goto('/unauthorized');
		}
	});
</script>

{#if $isLoading}
	<!-- Loading State -->
	<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
		<div class="text-center">
			<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
			<p class="mt-4 text-gray-600 dark:text-gray-400">Loading...</p>
		</div>
	</div>
{:else if !$isAuthenticated && !isPublicRoute}
	<!-- Not authenticated and not on public route - will redirect -->
	<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
		<div class="text-center">
			<p class="text-gray-600 dark:text-gray-400">Redirecting to login...</p>
		</div>
	</div>
{:else if $isAuthenticated && requiredRole && !hasRequiredRole()}
	<!-- Insufficient permissions -->
	<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
		<div class="text-center max-w-md mx-auto px-4">
			<div class="w-16 h-16 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center mx-auto mb-4">
				<svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
				</svg>
			</div>
			<h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-2">
				Access Denied
			</h2>
			<p class="text-gray-600 dark:text-gray-400 mb-6">
				You don't have permission to access this page. This action requires {requiredRole} privileges.
			</p>
			<button
				onclick={() => goto('/')}
				class="bg-primary text-white px-4 py-2 rounded-md hover:bg-primary-hover transition-colors"
			>
				Go to Dashboard
			</button>
		</div>
	</div>
{:else}
	<!-- Render children if authenticated and authorized -->
	{@render children?.()}
{/if}