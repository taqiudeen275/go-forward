<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification } from '$lib/stores';
	import type { User, UserFilter } from '$lib/types';

	let users: User[] = [];
	let loading = false;
	let showCreateModal = false;
	let showPromoteModal = false;
	let selectedUser: User | null = null;
	let filter: UserFilter = { limit: 20, offset: 0 };
	let total = 0;

	// Create user form
	let createForm = {
		email: '',
		phone: '',
		username: '',
		password: '',
		confirmPassword: ''
	};

	// Promote user form
	let promoteForm = {
		admin_level: 'moderator' as const,
		reason: '',
		assigned_tables: [] as string[]
	};

	onMount(() => {
		loadUsers();
	});

	async function loadUsers() {
		loading = true;
		try {
			const response = await api.listUsers(filter);
			users = response.data?.data || [];
			total = response.data?.total || 0;
		} catch (error) {
			addNotification('error', 'Failed to load users');
		} finally {
			loading = false;
		}
	}

	async function createUser() {
		if (createForm.password !== createForm.confirmPassword) {
			addNotification('error', 'Passwords do not match');
			return;
		}

		try {
			await api.createUser({
				email: createForm.email || undefined,
				phone: createForm.phone || undefined,
				username: createForm.username || undefined,
				password: createForm.password
			});
			
			addNotification('success', 'User created successfully');
			showCreateModal = false;
			resetCreateForm();
			loadUsers();
		} catch (error) {
			addNotification('error', `Failed to create user: ${error}`);
		}
	}

	async function promoteUser() {
		if (!selectedUser) return;

		try {
			await api.promoteUser(selectedUser.id, {
				admin_level: promoteForm.admin_level,
				reason: promoteForm.reason,
				assigned_tables: promoteForm.assigned_tables
			});
			
			addNotification('success', 'User promoted successfully');
			showPromoteModal = false;
			resetPromoteForm();
			loadUsers();
		} catch (error) {
			addNotification('error', `Failed to promote user: ${error}`);
		}
	}

	async function lockUser(user: User) {
		const reason = prompt('Enter reason for locking this user:');
		if (!reason) return;

		try {
			await api.lockUser(user.id, reason);
			addNotification('success', 'User locked successfully');
			loadUsers();
		} catch (error) {
			addNotification('error', `Failed to lock user: ${error}`);
		}
	}

	async function unlockUser(user: User) {
		try {
			await api.unlockUser(user.id);
			addNotification('success', 'User unlocked successfully');
			loadUsers();
		} catch (error) {
			addNotification('error', `Failed to unlock user: ${error}`);
		}
	}

	async function deleteUser(user: User) {
		if (!confirm(`Are you sure you want to delete user ${user.email || user.username}?`)) {
			return;
		}

		try {
			await api.deleteUser(user.id);
			addNotification('success', 'User deleted successfully');
			loadUsers();
		} catch (error) {
			addNotification('error', `Failed to delete user: ${error}`);
		}
	}

	function resetCreateForm() {
		createForm = {
			email: '',
			phone: '',
			username: '',
			password: '',
			confirmPassword: ''
		};
	}

	function resetPromoteForm() {
		promoteForm = {
			admin_level: 'moderator',
			reason: '',
			assigned_tables: []
		};
	}

	function openPromoteModal(user: User) {
		selectedUser = user;
		showPromoteModal = true;
	}

	function formatDate(dateString: string) {
		return new Date(dateString).toLocaleDateString();
	}

	function isUserLocked(user: User) {
		return user.locked_until && new Date(user.locked_until) > new Date();
	}

	function getAdminLevelBadge(level?: string) {
		if (!level) return '';
		
		const colors = {
			system_admin: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
			super_admin: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
			regular_admin: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
			moderator: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
		};
		
		return colors[level as keyof typeof colors] || '';
	}

	// Pagination
	function nextPage() {
		if (filter.offset + filter.limit < total) {
			filter.offset += filter.limit;
			loadUsers();
		}
	}

	function prevPage() {
		if (filter.offset > 0) {
			filter.offset = Math.max(0, filter.offset - filter.limit);
			loadUsers();
		}
	}
</script>

<svelte:head>
	<title>User Management - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex justify-between items-center">
		<div>
			<h1 class="text-2xl font-bold text-gray-900 dark:text-white">User Management</h1>
			<p class="text-gray-600 dark:text-gray-400">Manage user accounts and permissions</p>
		</div>
		<button
			type="button"
			class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
			on:click={() => showCreateModal = true}
		>
			Create User
		</button>
	</div>

	<!-- Filters -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Search
				</label>
				<input
					type="text"
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					placeholder="Search by email, username, or phone"
					bind:value={filter.search}
					on:input={loadUsers}
				/>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Admin Level
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.admin_level}
					on:change={loadUsers}
				>
					<option value="">All Users</option>
					<option value="system_admin">System Admin</option>
					<option value="super_admin">Super Admin</option>
					<option value="regular_admin">Regular Admin</option>
					<option value="moderator">Moderator</option>
				</select>
			</div>
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
					Verification Status
				</label>
				<select
					class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
					bind:value={filter.verified}
					on:change={loadUsers}
				>
					<option value="">All</option>
					<option value={true}>Verified</option>
					<option value={false}>Unverified</option>
				</select>
			</div>
		</div>
	</div>

	<!-- Users table -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
		<div class="overflow-x-auto">
			<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
				<thead class="bg-gray-50 dark:bg-gray-700">
					<tr>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							User
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Admin Level
						</th>
						<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
							Status
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
								Loading users...
							</td>
						</tr>
					{:else if users.length === 0}
						<tr>
							<td colspan="5" class="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
								No users found
							</td>
						</tr>
					{:else}
						{#each users as user}
							<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
								<td class="px-6 py-4 whitespace-nowrap">
									<div class="flex items-center">
										<div class="h-10 w-10 rounded-full bg-blue-500 flex items-center justify-center">
											<span class="text-sm font-medium text-white">
												{(user.email || user.username || 'U').charAt(0).toUpperCase()}
											</span>
										</div>
										<div class="ml-4">
											<div class="text-sm font-medium text-gray-900 dark:text-white">
												{user.email || user.username || 'No identifier'}
											</div>
											{#if user.phone}
												<div class="text-sm text-gray-500 dark:text-gray-400">
													{user.phone}
												</div>
											{/if}
										</div>
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap">
									{#if user.admin_level}
										<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full {getAdminLevelBadge(user.admin_level)}">
											{user.admin_level.replace('_', ' ').toUpperCase()}
										</span>
									{:else}
										<span class="text-sm text-gray-500 dark:text-gray-400">User</span>
									{/if}
								</td>
								<td class="px-6 py-4 whitespace-nowrap">
									<div class="flex flex-col space-y-1">
										{#if isUserLocked(user)}
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
												Locked
											</span>
										{:else}
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
												Active
											</span>
										{/if}
										{#if user.email_verified}
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
												Email Verified
											</span>
										{/if}
										{#if user.mfa_enabled}
											<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
												MFA Enabled
											</span>
										{/if}
									</div>
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
									{user.last_login ? formatDate(user.last_login) : 'Never'}
								</td>
								<td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
									{#if !user.admin_level}
										<button
											type="button"
											class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
											on:click={() => openPromoteModal(user)}
										>
											Promote
										</button>
									{/if}
									{#if isUserLocked(user)}
										<button
											type="button"
											class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300"
											on:click={() => unlockUser(user)}
										>
											Unlock
										</button>
									{:else}
										<button
											type="button"
											class="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300"
											on:click={() => lockUser(user)}
										>
											Lock
										</button>
									{/if}
									<button
										type="button"
										class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
										on:click={() => deleteUser(user)}
									>
										Delete
									</button>
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

<!-- Create User Modal -->
{#if showCreateModal}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showCreateModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
				<form on:submit|preventDefault={createUser}>
					<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Create New User
						</h3>
						
						<div class="space-y-4">
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Email
								</label>
								<input
									type="email"
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={createForm.email}
								/>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Phone
								</label>
								<input
									type="tel"
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={createForm.phone}
								/>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Username
								</label>
								<input
									type="text"
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={createForm.username}
								/>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Password *
								</label>
								<input
									type="password"
									required
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={createForm.password}
								/>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Confirm Password *
								</label>
								<input
									type="password"
									required
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={createForm.confirmPassword}
								/>
							</div>
						</div>
					</div>
					
					<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
						<button
							type="submit"
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
						>
							Create User
						</button>
						<button
							type="button"
							class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
							on:click={() => showCreateModal = false}
						>
							Cancel
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
{/if}

<!-- Promote User Modal -->
{#if showPromoteModal && selectedUser}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showPromoteModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
				<form on:submit|preventDefault={promoteUser}>
					<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Promote User to Admin
						</h3>
						
						<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
							Promoting: <strong>{selectedUser.email || selectedUser.username}</strong>
						</p>
						
						<div class="space-y-4">
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Admin Level *
								</label>
								<select
									required
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									bind:value={promoteForm.admin_level}
								>
									<option value="moderator">Moderator</option>
									<option value="regular_admin">Regular Admin</option>
									<option value="super_admin">Super Admin</option>
									<option value="system_admin">System Admin</option>
								</select>
							</div>
							
							<div>
								<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
									Reason
								</label>
								<textarea
									class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
									rows="3"
									placeholder="Reason for promotion..."
									bind:value={promoteForm.reason}
								></textarea>
							</div>
						</div>
					</div>
					
					<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
						<button
							type="submit"
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
						>
							Promote User
						</button>
						<button
							type="button"
							class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
							on:click={() => showPromoteModal = false}
						>
							Cancel
						</button>
					</div>
				</form>
			</div>
		</div>
	</div>
{/if}