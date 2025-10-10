<script lang="ts">
	import { theme, themeActions, roleThemes, type AdminRole } from '$lib/stores/theme';
	import { currentUser, authActions } from '$lib/stores/auth';
	import { page } from '$app/stores';
	import { writable } from 'svelte/store';
	import { getPath, isCurrentPath } from '$lib/utils/navigation';
	
	// Navigation state
	const mobileMenuOpen = writable(false);
	
	// Navigation items based on role
	const navigationItems = $derived(getNavigationItems($currentUser?.role || 'moderator'));
	
	function getNavigationItems(role: AdminRole) {
		const baseItems = [
			{ name: 'Dashboard', href: '/', icon: '📊' },
			{ name: 'Users', href: '/users', icon: '👥' }
		];
		
		const roleSpecificItems = {
			'system-admin': [
				...baseItems,
				{ name: 'SQL Editor', href: '/sql', icon: '💾' },
				{ name: 'System Config', href: '/system', icon: '🔧' },
				{ name: 'Admin Management', href: '/admins', icon: '👑' },
				{ name: 'Security', href: '/security', icon: '🔒' },
				{ name: 'Audit Logs', href: '/audit', icon: '📋' }
			],
			'super-admin': [
				...baseItems,
				{ name: 'Tables', href: '/tables', icon: '🗃️' },
				{ name: 'Storage', href: '/storage', icon: '📁' },
				{ name: 'Analytics', href: '/analytics', icon: '📈' },
				{ name: 'Settings', href: '/settings', icon: '⚙️' }
			],
			'regular-admin': [
				...baseItems,
				{ name: 'Content', href: '/content', icon: '📝' },
				{ name: 'Reports', href: '/reports', icon: '📊' }
			],
			'moderator': [
				{ name: 'Dashboard', href: '/', icon: '📊' },
				{ name: 'Moderation', href: '/moderation', icon: '🛡️' },
				{ name: 'Reports', href: '/reports', icon: '📋' }
			]
		};
		
		return roleSpecificItems[role] || baseItems;
	}
	
	function toggleMobileMenu() {
		mobileMenuOpen.update(open => !open);
	}
	
	function closeMobileMenu() {
		mobileMenuOpen.set(false);
	}
	
	function isActiveRoute(href: string): boolean {
		return isCurrentPath(href, $page.url.pathname);
	}
</script>

<!-- Mobile menu backdrop -->
{#if $mobileMenuOpen}
	<div 
		class="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
		onclick={closeMobileMenu}
		onkeydown={(e) => e.key === 'Escape' && closeMobileMenu()}
		role="button"
		tabindex="0"
	></div>
{/if}

<!-- Navigation -->
<nav class="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-50">
	<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
		<div class="flex justify-between h-16">
			<!-- Left side - Logo and main nav -->
			<div class="flex">
				<!-- Logo -->
				<div class="flex-shrink-0 flex items-center">
					<div class="flex items-center space-x-2">
						<div class="w-8 h-8 bg-primary rounded-lg flex items-center justify-center text-white font-bold">
							GF
						</div>
						<span class="text-xl font-semibold text-gray-900 dark:text-white">
							Admin
						</span>
					</div>
				</div>
				
				<!-- Desktop navigation -->
				<div class="hidden lg:ml-6 lg:flex lg:space-x-8">
					{#each navigationItems as item}
						<a
							href={getPath(item.href)}
							class="inline-flex items-center px-1 pt-1 text-sm font-medium transition-colors
								{isActiveRoute(item.href) 
									? 'border-b-2 border-primary text-primary' 
									: 'text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white border-b-2 border-transparent hover:border-gray-300'
								}"
						>
							<span class="mr-2">{item.icon}</span>
							{item.name}
						</a>
					{/each}
				</div>
			</div>
			
			<!-- Right side - Theme toggle, user menu, mobile menu button -->
			<div class="flex items-center space-x-4">
				<!-- Theme toggle -->
				<button
					onclick={themeActions.toggleMode}
					class="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white 
						   rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
					title="Toggle theme"
				>
					{#if $theme.isDark}
						<span class="text-lg">☀️</span>
					{:else}
						<span class="text-lg">🌙</span>
					{/if}
				</button>
				
				<!-- Role indicator -->
				{#if $currentUser}
					<div class="hidden sm:flex items-center space-x-2 px-3 py-1 rounded-full bg-gray-100 dark:bg-gray-800">
						<span class="text-sm">{roleThemes[$currentUser.role].icon}</span>
						<span class="text-xs font-medium text-gray-600 dark:text-gray-300">
							{roleThemes[$currentUser.role].name}
						</span>
					</div>
				{/if}
				
				<!-- User menu -->
				{#if $currentUser}
					<div class="relative">
						<button
							class="flex items-center space-x-2 p-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
							title="User menu"
							onclick={() => authActions.logout()}
						>
							<div class="w-8 h-8 bg-gray-300 dark:bg-gray-600 rounded-full flex items-center justify-center">
								<span class="text-sm font-medium text-gray-700 dark:text-gray-200">
									{$currentUser.name.split(' ').map(n => n[0]).join('')}
								</span>
							</div>
							<span class="hidden md:block text-sm font-medium text-gray-700 dark:text-gray-200">
								{$currentUser.name}
							</span>
							<svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
							</svg>
						</button>
					</div>
				{/if}
				
				<!-- Mobile menu button -->
				<button
					onclick={toggleMobileMenu}
					class="lg:hidden p-2 text-gray-500 hover:text-gray-700 dark:text-gray-300 dark:hover:text-white 
						   rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
					title="Toggle mobile menu"
				>
					{#if $mobileMenuOpen}
						<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
					{:else}
						<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
						</svg>
					{/if}
				</button>
			</div>
		</div>
	</div>
	
	<!-- Mobile navigation menu -->
	<div class="lg:hidden {$mobileMenuOpen ? 'block' : 'hidden'}">
		<div class="pt-2 pb-3 space-y-1 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
			{#each navigationItems as item}
				<a
					href={getPath(item.href)}
					onclick={closeMobileMenu}
					class="block pl-3 pr-4 py-2 text-base font-medium transition-colors
						{isActiveRoute(item.href)
							? 'bg-primary bg-opacity-10 border-r-4 border-primary text-primary'
							: 'text-gray-600 hover:text-gray-900 hover:bg-gray-50 dark:text-gray-300 dark:hover:text-white dark:hover:bg-gray-800'
						}"
				>
					<span class="mr-3">{item.icon}</span>
					{item.name}
				</a>
			{/each}
			
			<!-- Mobile role indicator -->
			{#if $currentUser}
				<div class="px-3 py-2 border-t border-gray-200 dark:border-gray-700 mt-2">
					<div class="flex items-center justify-between">
						<div class="flex items-center space-x-2">
							<span class="text-lg">{roleThemes[$currentUser.role].icon}</span>
							<div>
								<div class="text-sm font-medium text-gray-900 dark:text-white">
									{roleThemes[$currentUser.role].name}
								</div>
								<div class="text-xs text-gray-500 dark:text-gray-400">
									{$currentUser.name}
								</div>
							</div>
						</div>
						<button
							onclick={() => authActions.logout()}
							class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-md"
							title="Logout"
						>
							<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
							</svg>
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
</nav>

<style>
	/* Custom focus styles */
	button:focus,
	a:focus {
		outline: 2px solid rgb(var(--color-primary));
		outline-offset: 2px;
	}
</style>