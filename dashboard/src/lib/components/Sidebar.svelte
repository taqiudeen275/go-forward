<script lang="ts">
	import { page } from '$app/stores';
	import { currentUser, sidebarOpen } from '../stores';

	interface MenuItem {
		name: string;
		href: string;
		icon: string;
		requiredCapability?: string;
		adminLevelRequired?: string[];
	}

	const menuItems: MenuItem[] = [
		{
			name: 'Dashboard',
			href: '/_/',
			icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z'
		},
		{
			name: 'Users',
			href: '/_/users',
			icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z',
			requiredCapability: 'can_manage_users'
		},
		{
			name: 'Admins',
			href: '/_/admins',
			icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
			adminLevelRequired: ['system_admin', 'super_admin']
		},
		{
			name: 'Sessions',
			href: '/_/sessions',
			icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
			requiredCapability: 'can_view_all_logs'
		},
		{
			name: 'Templates',
			href: '/_/templates',
			icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
			requiredCapability: 'can_manage_templates'
		},
		{
			name: 'Authentication',
			href: '/_/auth-config',
			icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
			adminLevelRequired: ['system_admin', 'super_admin']
		},
		{
			name: 'MFA Setup',
			href: '/_/mfa',
			icon: 'M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4'
		}
	];

	function canAccessMenuItem(item: MenuItem): boolean {
		if (!$currentUser) return false;

		// Check admin level requirement
		if (item.adminLevelRequired) {
			if (!$currentUser.admin_level || !item.adminLevelRequired.includes($currentUser.admin_level)) {
				return false;
			}
		}

		// Check capability requirement
		if (item.requiredCapability) {
			if (!$currentUser.capabilities) return false;
			
			const capability = item.requiredCapability as keyof typeof $currentUser.capabilities;
			return $currentUser.capabilities[capability] === true;
		}

		return true;
	}

	function isCurrentPage(href: string): boolean {
		return $page.url.pathname === href || ($page.url.pathname.startsWith(href) && href !== '/_/');
	}

	function closeSidebar() {
		sidebarOpen.set(false);
	}
</script>

<!-- Desktop sidebar -->
<div class="hidden lg:flex lg:flex-shrink-0">
	<div class="flex flex-col w-64">
		<div class="flex flex-col flex-grow bg-white dark:bg-gray-800 pt-5 pb-4 overflow-y-auto border-r border-gray-200 dark:border-gray-700">
			<!-- Logo -->
			<div class="flex items-center flex-shrink-0 px-4">
				<div class="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center">
					<span class="text-white font-bold text-lg">GF</span>
				</div>
				<span class="ml-3 text-lg font-semibold text-gray-900 dark:text-white">Go Forward</span>
			</div>

			<!-- Navigation -->
			<nav class="mt-8 flex-1 px-2 space-y-1">
				{#each menuItems as item}
					{#if canAccessMenuItem(item)}
						<a
							href={item.href}
							class="group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors duration-150 {isCurrentPage(item.href)
								? 'bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100'
								: 'text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white'}"
						>
							<svg
								class="mr-3 h-5 w-5 {isCurrentPage(item.href)
									? 'text-blue-500 dark:text-blue-400'
									: 'text-gray-400 group-hover:text-gray-500 dark:group-hover:text-gray-300'}"
								fill="none"
								viewBox="0 0 24 24"
								stroke="currentColor"
							>
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={item.icon} />
							</svg>
							{item.name}
						</a>
					{/if}
				{/each}
			</nav>
		</div>
	</div>
</div>

<!-- Mobile sidebar -->
<div class="lg:hidden">
	<div class="fixed inset-0 z-50 flex {$sidebarOpen ? '' : 'pointer-events-none'}">
		<div class="relative flex-1 flex flex-col max-w-xs w-full bg-white dark:bg-gray-800 transform transition-transform duration-300 ease-in-out {$sidebarOpen ? 'translate-x-0' : '-translate-x-full'}">
			<!-- Close button -->
			<div class="absolute top-0 right-0 -mr-12 pt-2">
				<button
					type="button"
					class="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
					on:click={closeSidebar}
				>
					<svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</button>
			</div>

			<div class="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
				<!-- Logo -->
				<div class="flex items-center flex-shrink-0 px-4">
					<div class="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center">
						<span class="text-white font-bold text-lg">GF</span>
					</div>
					<span class="ml-3 text-lg font-semibold text-gray-900 dark:text-white">Go Forward</span>
				</div>

				<!-- Navigation -->
				<nav class="mt-8 px-2 space-y-1">
					{#each menuItems as item}
						{#if canAccessMenuItem(item)}
							<a
								href={item.href}
								class="group flex items-center px-2 py-2 text-base font-medium rounded-md transition-colors duration-150 {isCurrentPage(item.href)
									? 'bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100'
									: 'text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white'}"
								on:click={closeSidebar}
							>
								<svg
									class="mr-4 h-6 w-6 {isCurrentPage(item.href)
										? 'text-blue-500 dark:text-blue-400'
										: 'text-gray-400 group-hover:text-gray-500 dark:group-hover:text-gray-300'}"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
								>
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={item.icon} />
								</svg>
								{item.name}
							</a>
						{/if}
					{/each}
				</nav>
			</div>
		</div>
	</div>
</div>