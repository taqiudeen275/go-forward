<script lang="ts">
	import { currentUser, sidebarOpen, theme } from '../stores';
	import { api } from '../api';
	import { addNotification } from '../stores';

	async function handleLogout() {
		try {
			await api.adminLogout();
			window.location.href = '/_/login';
		} catch (error) {
			addNotification('error', 'Failed to logout');
		}
	}

	function toggleSidebar() {
		sidebarOpen.update(open => !open);
	}

	function toggleTheme() {
		theme.update(current => current === 'light' ? 'dark' : 'light');
	}
</script>

<header class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
	<div class="flex items-center justify-between px-6 py-4">
		<!-- Left side -->
		<div class="flex items-center space-x-4">
			<!-- Mobile menu button -->
			<button
				type="button"
				class="lg:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
				on:click={toggleSidebar}
			>
				<svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
				</svg>
			</button>

			<!-- Page title -->
			<h1 class="text-xl font-semibold text-gray-900 dark:text-white">
				Admin Dashboard
			</h1>
		</div>

		<!-- Right side -->
		<div class="flex items-center space-x-4">
			<!-- Theme toggle -->
			<button
				type="button"
				class="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
				on:click={toggleTheme}
			>
				{#if $theme === 'light'}
					<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
					</svg>
				{:else}
					<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
					</svg>
				{/if}
			</button>

			<!-- User menu -->
			{#if $currentUser}
				<div class="relative">
					<div class="flex items-center space-x-3">
						<!-- User avatar -->
						<div class="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center">
							<span class="text-sm font-medium text-white">
								{($currentUser.email || $currentUser.username || 'U').charAt(0).toUpperCase()}
							</span>
						</div>

						<!-- User info -->
						<div class="hidden md:block">
							<div class="text-sm font-medium text-gray-900 dark:text-white">
								{$currentUser.email || $currentUser.username || 'User'}
							</div>
							<div class="text-xs text-gray-500 dark:text-gray-400 capitalize">
								{$currentUser.admin_level?.replace('_', ' ') || 'User'}
							</div>
						</div>

						<!-- Logout button -->
						<button
							type="button"
							class="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
							on:click={handleLogout}
							title="Logout"
						>
							<svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
							</svg>
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
</header>