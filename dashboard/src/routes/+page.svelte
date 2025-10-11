<script lang="ts">
	import { onMount } from 'svelte';
	import { currentUser } from '$lib/stores';
	import { api } from '$lib/api';

	let stats = {
		totalUsers: 0,
		totalAdmins: 0,
		activeSessions: 0,
		totalTemplates: 0
	};

	onMount(async () => {
		// Load dashboard statistics
		try {
			const [usersResponse, adminsResponse, sessionsResponse, templatesResponse] = await Promise.all([
				api.listUsers({ limit: 1 }),
				api.listAdmins({ limit: 1 }),
				api.listSessions(),
				api.listTemplates({ limit: 1 })
			]);

			stats = {
				totalUsers: usersResponse.data?.total || 0,
				totalAdmins: adminsResponse.data?.total || 0,
				activeSessions: sessionsResponse.data?.length || 0,
				totalTemplates: templatesResponse.data?.total || 0
			};
		} catch (error) {
			console.error('Failed to load dashboard stats:', error);
		}
	});
</script>

<svelte:head>
	<title>Admin Dashboard - Go Forward</title>
</svelte:head>

<div class="space-y-6">
	<!-- Welcome section -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<h1 class="text-2xl font-bold text-gray-900 dark:text-white mb-2">
			Welcome back, {$currentUser?.email || $currentUser?.username || 'Admin'}!
		</h1>
		<p class="text-gray-600 dark:text-gray-400">
			You are logged in as a <span class="font-medium capitalize">{$currentUser?.admin_level?.replace('_', ' ') || 'User'}</span>
		</p>
	</div>

	<!-- Stats grid -->
	<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
		<!-- Total Users -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Total Users</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">{stats.totalUsers}</dd>
					</dl>
				</div>
			</div>
		</div>

		<!-- Total Admins -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Total Admins</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">{stats.totalAdmins}</dd>
					</dl>
				</div>
			</div>
		</div>

		<!-- Active Sessions -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-yellow-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Active Sessions</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">{stats.activeSessions}</dd>
					</dl>
				</div>
			</div>
		</div>

		<!-- Total Templates -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-purple-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Templates</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">{stats.totalTemplates}</dd>
					</dl>
				</div>
			</div>
		</div>
	</div>

	<!-- Quick actions -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Quick Actions</h2>
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#if $currentUser?.capabilities?.can_manage_users}
				<a
					href="/_/users"
					class="flex items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
				>
					<svg class="w-6 h-6 text-blue-500 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
					</svg>
					<div>
						<div class="font-medium text-gray-900 dark:text-white">Manage Users</div>
						<div class="text-sm text-gray-500 dark:text-gray-400">View and manage user accounts</div>
					</div>
				</a>
			{/if}

			{#if $currentUser?.admin_level === 'system_admin' || $currentUser?.admin_level === 'super_admin'}
				<a
					href="/_/admins"
					class="flex items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
				>
					<svg class="w-6 h-6 text-green-500 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
					</svg>
					<div>
						<div class="font-medium text-gray-900 dark:text-white">Manage Admins</div>
						<div class="text-sm text-gray-500 dark:text-gray-400">View and manage admin accounts</div>
					</div>
				</a>
			{/if}

			{#if $currentUser?.capabilities?.can_manage_templates}
				<a
					href="/_/templates"
					class="flex items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
				>
					<svg class="w-6 h-6 text-purple-500 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
					</svg>
					<div>
						<div class="font-medium text-gray-900 dark:text-white">Manage Templates</div>
						<div class="text-sm text-gray-500 dark:text-gray-400">Configure email and SMS templates</div>
					</div>
				</a>
			{/if}
		</div>
	</div>
</div>