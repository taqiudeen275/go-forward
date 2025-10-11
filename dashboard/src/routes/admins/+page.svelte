<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification, currentUser } from '$lib/stores';
	import type { User, AdminFilter, AdminSession } from '$lib/types';

	let admins: User[] = [];
	let loading = false;
	let showSessionsModal = false;
	let selectedAdmin: User | null = null;
	let adminSessions: AdminSession[] = [];
	let filter: AdminFilter = { limit: 20, offset: 0 };
	let total = 0;

	onMount(() => {
		loadAdmins();
	});

	async function loadAdmins() {
		loading = true;
		try {
			const response = await api.listAdmins(filter);
			admins = response.data?.data || [];
			total = response.data?.total || 0;
		} catch (error) {
			addNotification('error', 'Failed to load admins');
		} finally {
			loading = false;
		}
	}

	async function loadAdminSessions(admin: User) {
		try {
			const response = await api.getAdminSessions(admin.id);
			adminSessions = response.data || [];
			selectedAdmin = admin;
			showSessionsModal = true;
		} catch (error) {
			addNotification('error', 'Failed to load admin sessions');
		}
	}

	async function revokeAdminSessions(admin: User) {
		if (!confirm(`Are you sure you want to revoke all sessions for ${admin.email || admin.username}?`)) {
			return;
		}

		try {
			await api.revokeAdminSessions(admin.id);
			addNotification('success', 'Admin sessions revoked successfully');
			if (selectedAdmin?.id === admin.id) {
				loadAdminSessions(admin);
			}
		} catch (error) {
			addNotification('error', `Failed to revoke admin sessions: ${error}`);
		}
	}

	async function demoteAdmin(admin: User) {
		const reason = prompt(`Enter reason for demoting ${admin.email || admin.username}:`);
		if (!reason) return;

		try {
			await api.demoteUser(admin.id, reason);
			addNotification('success', 'Admin demoted successfully');
			loadAdmins();
		} catch (error) {
			addNotification('error', `Failed to demote admin: ${error}`);
		}
	}

	function formatDate(dateString: string) {
		return new Date(dateString).toLocaleDateString() + ' ' + new Date(dateString).toLocaleTimeString();
	}

	function getAdminLevelBadge(level: string) {
		const colors = {
			system_admin: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
			super_admin: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
			regular_admin: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
			moderator: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
		};
		
		return colors[level as keyof typeof colors] || '';
	}

	function getAdminLevelHierarchy(level: string): number {
		const hierarchy = {
			system_admin: 4,
			super_admin: 3,
			regular_admin: 2,
			moderator: 1
		};
		return hierarchy[level as keyof typeof hierarchy] || 0;
	}

	function canManageAdmin(admin: User): boolean {
		if (!$currentUser?.admin_level) return false;
		
		const currentLevel = getAdminLevelHierarchy($currentUser.admin_level);
		const targetLevel = getAdminLevelHierarchy(admin.admin_level || '');
		
		// Can only manage admins of lower level
		return currentLevel > targetLevel;
	}

	function getCapabilitiesSummary(capabilities: any): string[] {
		if (!capabilities) return [];
		
		const summary = [];
		if (capabilities.can_access_sql) summary.push('SQL Access');
		if (capabilities.can_manage_database) summary.push('Database Management');
		if (capabilities.can_manage_system) summary.push('System Management');
		if (capabilities.can_create_admins) summary.push('Admin Creation');
		if (capabilities.can_manage_all_tables) summary.push('All Tables');
		if (capabilities.can_manage_templates) summary.push('Templates');
		if (capabilities.can_manage_cron_jobs) summary.push('Cron Jobs');
		
		return summary;
	}

	// Pagination
	function nextPage() {
		if (filter.offset + filter.limit < total) {
			filter.offset += filter.limit;
			loadAdmins();
		}
	}

	function prevPage() {
		if (filter.offset > 0) {
			filter.offset = Math.max(0, filter.offset - filter.limit);
			loadAdmins();
		}
	}
</script>

<svelte:head>
	<title>Admin Management - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex justify-between items-center">
		<div>
			<h1 class="text-2xl font-bold text-gray-900 dark:text-white">Admin Management</h1>
			<p class="text-gray-600 dark:text-gray-400">Manage admin accounts and their permissions</p>
		</div>
	</div>

	<!-- Admin Hierarchy Info -->
	<div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4">
		<h3 class="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">Admin Hierarchy</h3>
		<div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
			<div class="flex items-center space-x-2">
				<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
					System Admin
				</span>
				<span class="text-blue-700 dark:text-blue-300">Full system access</span>
			</div>
			<div class="flex items-center space-x-2">
				<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
					Super Admin
				</span>
				<span class="text-blue-700 dark:text-blue-300">Business operations</span>
			</div>
			<div class="flex items-center space-x-2">
				<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
					Regular Admin
				</span>
				<span class="text-blue-700 dark:text-blue-300">Limited scope</span>
			</div>
			<div class="flex items-center space-x-2">
				<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
					Moderator
				</span>
				<span class="text-blue-700 dark:text-blue-300">Read-only + moderation</span>
			</div>
		</div>
	</div>

	<!-- Filters -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Search
				</label>
				<input
					type="text"
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					placeholder="Search by email or username"
					bind:value={filter.search}
					on:input={loadAdmins}
				/>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Admin Level
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.level}
					on:change={loadAdmins}
				>
					<option value="">All Levels</option>
					<option value="system_admin">System Admin</option>
					<option value="super_admin">Super Admin</option>
					<option value="regular_admin">Regular Admin</option>
					<option value="moderator">Moderator</option>
				</select>
			</div>
		</div>
	</div>

	<!-- Admins table -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
		<div class="overflow-x-auto">
			<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
				<thead class="bg-gray-50 dark:bg-gray-700">
					<tr>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Admin
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Level
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Capabilities
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Last Login
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Actions
						</th>
					</tr>
				</thead>
				<tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
					{#if loading}
						<tr>
							<td colspan="5" class="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
								Loading admins...
							</td>
						</tr>
					{:else if admins.length === 0}
						<tr>
							<td colspan="5" class="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
								No admins found
							</td>
						</tr>
					{:else}
						{#each admins as admin}
							<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
								<td class="px-6 py-4 whitespace-nowrap">
									<div class="flex items-center">
										<div class="h-10 w-10 rounded-full bg-blue-500 flex items-center justify-center">
											<span class="text-sm font-medium text-white">
												{(admin.email || admin.username || 'A').charAt(0).toUpperCase()}
											</span>
										</div>
										<div class="ml-4">
											<div class="text-sm font-medium text-gray-900 dark:text-white">
												{admin.email || admin.username || 'No identifier'}
											</div>
											{#if admin.assigned_tables && admin.assigned_tables.length > 0}
												<div class="text-sm text-gray-500 dark:text-gray-400">
													Tables: {admin.assigned_tables.join(', ')}
												</div>
											{/if}
										</div>
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap">
									<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full {getAdminLevelBadge(admin.admin_level || '')}">
										{admin.admin_level?.replace('_', ' ').toUpperCase()}
									</span>
									{#if admin.mfa_enabled}
										<div class="mt-1">
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
												MFA Enabled
											</span>
										</div>
									{/if}
								</td>
								<td class="px-6 py-4">
									<div class="text-sm text-gray-900 dark:text-white">
										{#each getCapabilitiesSummary(admin.capabilities) as capability}
											<span class="inline-block bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-xs px-2 py-1 rounded mr-1 mb-1">
												{capability}
											</span>
										{/each}
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
									{admin.last_login ? formatDate(admin.last_login) : 'Never'}
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
									<button
										type="button"
										class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
										on:click={() => loadAdminSessions(admin)}
									>
										Sessions
									</button>
									{#if canManageAdmin(admin)}
										<button
											type="button"
											class="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300"
											on:click={() => revokeAdminSessions(admin)}
										>
											Revoke Sessions
										</button>
										<button
											type="button"
											class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
											on:click={() => demoteAdmin(admin)}
										>
											Demote
										</button>
									{/if}
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<!-- Pagination -->
		<div class="bg-white dark:bg-gray-800 px-4 py-3 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 sm:px-6">
			<div class="flex-1 flex justify-between sm:hidden">
				<button
					type="button"
					class="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
					disabled={filter.offset === 0}
					on:click={prevPage}
				>
					Previous
				</button>
				<button
					type="button"
					class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
					disabled={filter.offset + filter.limit >= total}
					on:click={nextPage}
				>
					Next
				</button>
			</div>
			<div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
				<div>
					<p class="text-sm text-gray-700 dark:text-gray-300">
						Showing <span class="font-medium">{filter.offset + 1}</span> to <span class="font-medium">{Math.min(filter.offset + filter.limit, total)}</span> of <span class="font-medium">{total}</span> results
					</p>
				</div>
				<div>
					<nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
						<button
							type="button"
							class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
							disabled={filter.offset === 0}
							on:click={prevPage}
						>
							Previous
						</button>
						<button
							type="button"
							class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
							disabled={filter.offset + filter.limit >= total}
							on:click={nextPage}
						>
							Next
						</button>
					</nav>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- Admin Sessions Modal -->
{#if showSessionsModal && selectedAdmin}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showSessionsModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
				<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
					<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
						Admin Sessions - {selectedAdmin.email || selectedAdmin.username}
					</h3>
					
					{#if adminSessions.length === 0}
						<p class="text-gray-500 dark:text-gray-400">No active sessions found.</p>
					{:else}
						<div class="overflow-x-auto">
							<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
								<thead class="bg-gray-50 dark:bg-gray-700">
									<tr>
										<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
											Session ID
										</th>
										<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
											IP Address
										</th>
										<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
											User Agent
										</th>
										<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
											Created
										</th>
										<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
											Last Activity
										</th>
									</tr>
								</thead>
								<tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
									{#each adminSessions as session}
										<tr>
											<td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">
												{session.id.substring(0, 8)}...
											</td>
											<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
												{session.ip_address || 'Unknown'}
											</td>
											<td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 max-w-xs truncate">
												{session.user_agent || 'Unknown'}
											</td>
											<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
												{formatDate(session.created_at)}
											</td>
											<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
												{formatDate(session.last_activity)}
											</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}
				</div>
				
				<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
					<button
						type="button"
						class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:w-auto sm:text-sm"
						on:click={() => showSessionsModal = false}
					>
						Close
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}