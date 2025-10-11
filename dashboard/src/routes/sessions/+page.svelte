<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification, currentUser } from '$lib/stores';
	import type { AdminSession } from '$lib/types';

	let sessions: AdminSession[] = [];
	let loading = false;
	let refreshInterval: number;

	onMount(() => {
		loadSessions();
		// Auto-refresh every 30 seconds
		refreshInterval = setInterval(loadSessions, 30000);
		
		return () => {
			if (refreshInterval) {
				clearInterval(refreshInterval);
			}
		};
	});

	async function loadSessions() {
		loading = true;
		try {
			const response = await api.listSessions();
			sessions = response.data || [];
		} catch (error) {
			addNotification('error', 'Failed to load sessions');
		} finally {
			loading = false;
		}
	}

	async function revokeSession(sessionId: string) {
		if (!confirm('Are you sure you want to revoke this session?')) {
			return;
		}

		try {
			await api.revokeSession(sessionId);
			addNotification('success', 'Session revoked successfully');
			loadSessions();
		} catch (error) {
			addNotification('error', `Failed to revoke session: ${error}`);
		}
	}

	async function revokeAllSessions() {
		if (!confirm('Are you sure you want to revoke ALL sessions? This will log out all users including yourself.')) {
			return;
		}

		try {
			await api.revokeAllSessions();
			addNotification('success', 'All sessions revoked successfully');
			// Redirect to login since current session is also revoked
			setTimeout(() => {
				window.location.href = '/_/login';
			}, 2000);
		} catch (error) {
			addNotification('error', `Failed to revoke all sessions: ${error}`);
		}
	}

	function formatDate(dateString: string) {
		return new Date(dateString).toLocaleDateString() + ' ' + new Date(dateString).toLocaleTimeString();
	}

	function getTimeAgo(dateString: string) {
		const now = new Date();
		const date = new Date(dateString);
		const diffMs = now.getTime() - date.getTime();
		const diffMins = Math.floor(diffMs / 60000);
		const diffHours = Math.floor(diffMins / 60);
		const diffDays = Math.floor(diffHours / 24);

		if (diffMins < 1) return 'Just now';
		if (diffMins < 60) return `${diffMins} minutes ago`;
		if (diffHours < 24) return `${diffHours} hours ago`;
		return `${diffDays} days ago`;
	}

	function isCurrentSession(session: AdminSession): boolean {
		// This would need to be determined by comparing with current session ID
		// For now, we'll use a simple heuristic based on recent activity
		const lastActivity = new Date(session.last_activity);
		const now = new Date();
		const diffMs = now.getTime() - lastActivity.getTime();
		return diffMs < 60000; // Less than 1 minute ago
	}

	function isExpired(session: AdminSession): boolean {
		return new Date(session.expires_at) < new Date();
	}

	function getSessionStatus(session: AdminSession): { text: string; color: string } {
		if (isExpired(session)) {
			return { text: 'Expired', color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' };
		}
		if (isCurrentSession(session)) {
			return { text: 'Current', color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' };
		}
		return { text: 'Active', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' };
	}

	function getBrowserInfo(userAgent: string): string {
		if (!userAgent) return 'Unknown Browser';
		
		if (userAgent.includes('Chrome')) return 'Chrome';
		if (userAgent.includes('Firefox')) return 'Firefox';
		if (userAgent.includes('Safari')) return 'Safari';
		if (userAgent.includes('Edge')) return 'Edge';
		return 'Unknown Browser';
	}

	function getOSInfo(userAgent: string): string {
		if (!userAgent) return 'Unknown OS';
		
		if (userAgent.includes('Windows')) return 'Windows';
		if (userAgent.includes('Mac')) return 'macOS';
		if (userAgent.includes('Linux')) return 'Linux';
		if (userAgent.includes('Android')) return 'Android';
		if (userAgent.includes('iOS')) return 'iOS';
		return 'Unknown OS';
	}
</script>

<svelte:head>
	<title>Session Management - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex justify-between items-center">
		<div>
			<h1 class="text-2xl font-bold text-gray-900 dark:text-white">Session Management</h1>
			<p class="text-gray-600 dark:text-gray-400">Monitor and manage active admin sessions</p>
		</div>
		<div class="flex space-x-3">
			<button
				type="button"
				class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
				disabled={loading}
				on:click={loadSessions}
			>
				{loading ? 'Refreshing...' : 'Refresh'}
			</button>
			{#if $currentUser?.capabilities?.can_manage_system}
				<button
					type="button"
					class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
					on:click={revokeAllSessions}
				>
					Revoke All Sessions
				</button>
			{/if}
		</div>
	</div>

	<!-- Session Statistics -->
	<div class="grid grid-cols-1 md:grid-cols-3 gap-6">
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Total Sessions</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">{sessions.length}</dd>
					</dl>
				</div>
			</div>
		</div>

		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Active Sessions</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">
							{sessions.filter(s => !isExpired(s)).length}
						</dd>
					</dl>
				</div>
			</div>
		</div>

		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<div class="flex items-center">
				<div class="flex-shrink-0">
					<div class="w-8 h-8 bg-red-500 rounded-md flex items-center justify-center">
						<svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
					</div>
				</div>
				<div class="ml-5 w-0 flex-1">
					<dl>
						<dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Expired Sessions</dt>
						<dd class="text-lg font-medium text-gray-900 dark:text-white">
							{sessions.filter(s => isExpired(s)).length}
						</dd>
					</dl>
				</div>
			</div>
		</div>
	</div>

	<!-- Sessions table -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
		<div class="px-4 py-5 sm:p-6">
			<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
				Active Sessions
			</h3>
			
			{#if loading && sessions.length === 0}
				<div class="text-center py-8">
					<div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
					<p class="mt-2 text-sm text-gray-500 dark:text-gray-400">Loading sessions...</p>
				</div>
			{:else if sessions.length === 0}
				<div class="text-center py-8">
					<svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
					</svg>
					<h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">No sessions found</h3>
					<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">There are no active admin sessions.</p>
				</div>
			{:else}
				<div class="overflow-x-auto">
					<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
						<thead class="bg-gray-50 dark:bg-gray-700">
							<tr>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									Session
								</th>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									User
								</th>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									Location & Device
								</th>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									Status
								</th>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									Last Activity
								</th>
								<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
									Actions
								</th>
							</tr>
						</thead>
						<tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
							{#each sessions as session}
								<tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
									<td class="px-6 py-4 whitespace-nowrap">
										<div class="text-sm">
											<div class="font-medium text-gray-900 dark:text-white font-mono">
												{session.id.substring(0, 8)}...
											</div>
											<div class="text-gray-500 dark:text-gray-400">
												Created: {formatDate(session.created_at)}
											</div>
											<div class="text-gray-500 dark:text-gray-400">
												Expires: {formatDate(session.expires_at)}
											</div>
										</div>
									</td>
									<td class="px-6 py-4 whitespace-nowrap">
										<div class="flex items-center">
											<div class="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center">
												<span class="text-xs font-medium text-white">
													{session.user_id.substring(0, 2).toUpperCase()}
												</span>
											</div>
											<div class="ml-3">
												<div class="text-sm font-medium text-gray-900 dark:text-white">
													{session.user_id.substring(0, 8)}...
												</div>
											</div>
										</div>
									</td>
									<td class="px-6 py-4">
										<div class="text-sm text-gray-900 dark:text-white">
											<div class="flex items-center space-x-2">
												<svg class="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
												</svg>
												<span>{session.ip_address || 'Unknown IP'}</span>
											</div>
											<div class="flex items-center space-x-2 mt-1">
												<svg class="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
												</svg>
												<span class="text-xs">
													{getBrowserInfo(session.user_agent || '')} on {getOSInfo(session.user_agent || '')}
												</span>
											</div>
										</div>
									</td>
									<td class="px-6 py-4 whitespace-nowrap">
										{@const status = getSessionStatus(session)}
										<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full {status.color}">
											{status.text}
										</span>
									</td>
									<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
										<div>{getTimeAgo(session.last_activity)}</div>
										<div class="text-xs">{formatDate(session.last_activity)}</div>
									</td>
									<td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
										{#if !isExpired(session)}
											<button
												type="button"
												class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
												on:click={() => revokeSession(session.id)}
											>
												Revoke
											</button>
										{:else}
											<span class="text-gray-400">Expired</span>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	</div>

	<!-- Session Security Info -->
	<div class="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
		<div class="flex">
			<div class="flex-shrink-0">
				<svg class="h-5 w-5 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
				</svg>
			</div>
			<div class="ml-3">
				<h3 class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
					Session Security
				</h3>
				<div class="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
					<ul class="list-disc list-inside space-y-1">
						<li>Sessions automatically expire after a period of inactivity</li>
						<li>Revoking a session will immediately log out the user</li>
						<li>Monitor for suspicious IP addresses or unusual activity patterns</li>
						<li>Current session is marked with a green "Current" badge</li>
					</ul>
				</div>
			</div>
		</div>
	</div>
</div>