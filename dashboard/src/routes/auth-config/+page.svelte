<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification } from '$lib/stores';
	import type { AuthConfig } from '$lib/types';

	let config: AuthConfig = {
		jwt_secret: '',
		access_token_expiration: '15m',
		refresh_token_expiration: '7d',
		enable_cookie_auth: true,
		cookie_http_only: true,
		cookie_secure: true,
		cookie_same_site: 'Strict',
		mfa_required_for_admins: false,
		password_min_length: 8,
		password_require_uppercase: true,
		password_require_lowercase: true,
		password_require_numbers: true,
		password_require_symbols: false,
		max_failed_attempts: 5,
		lockout_duration: '15m'
	};

	let loading = false;
	let saving = false;
	let originalConfig: AuthConfig;

	onMount(() => {
		loadConfig();
	});

	async function loadConfig() {
		loading = true;
		try {
			const response = await api.getAuthConfig();
			config = response.data || config;
			originalConfig = { ...config };
		} catch (error) {
			addNotification('error', 'Failed to load authentication configuration');
		} finally {
			loading = false;
		}
	}

	async function saveConfig() {
		saving = true;
		try {
			await api.updateAuthConfig(config);
			addNotification('success', 'Authentication configuration updated successfully');
			originalConfig = { ...config };
		} catch (error) {
			addNotification('error', `Failed to update configuration: ${error}`);
		} finally {
			saving = false;
		}
	}

	function resetConfig() {
		config = { ...originalConfig };
	}

	function hasChanges(): boolean {
		return JSON.stringify(config) !== JSON.stringify(originalConfig);
	}

	function generateNewSecret() {
		// Generate a random 32-character secret
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		let result = '';
		for (let i = 0; i < 32; i++) {
			result += chars.charAt(Math.floor(Math.random() * chars.length));
		}
		config.jwt_secret = result;
	}

	function getPasswordStrengthIndicator(): { score: number; text: string; color: string } {
		let score = 0;
		let requirements = [];

		if (config.password_min_length >= 8) score++;
		if (config.password_require_uppercase) { score++; requirements.push('uppercase'); }
		if (config.password_require_lowercase) { score++; requirements.push('lowercase'); }
		if (config.password_require_numbers) { score++; requirements.push('numbers'); }
		if (config.password_require_symbols) { score++; requirements.push('symbols'); }

		const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-blue-500', 'bg-green-500'];
		const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

		return {
			score,
			text: texts[Math.min(score - 1, 4)] || 'Very Weak',
			color: colors[Math.min(score - 1, 4)] || 'bg-red-500'
		};
	}

	$: passwordStrength = getPasswordStrengthIndicator();
</script>

<svelte:head>
	<title>Authentication Configuration - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex justify-between items-center">
		<div>
			<h1 class="text-2xl font-bold text-gray-900 dark:text-white">Authentication Configuration</h1>
			<p class="text-gray-600 dark:text-gray-400">Configure authentication settings and security policies</p>
		</div>
		<div class="flex space-x-3">
			{#if hasChanges()}
				<button
					type="button"
					class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md text-sm font-medium"
					on:click={resetConfig}
				>
					Reset
				</button>
			{/if}
			<button
				type="button"
				class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
				disabled={saving || !hasChanges()}
				on:click={saveConfig}
			>
				{saving ? 'Saving...' : 'Save Changes'}
			</button>
		</div>
	</div>

	{#if loading}
		<div class="text-center py-8">
			<div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
			<p class="mt-2 text-sm text-gray-500 dark:text-gray-400">Loading configuration...</p>
		</div>
	{:else}
		<!-- JWT Configuration -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">JWT Configuration</h2>
			
			<div class="space-y-4">
				<div>
					<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						JWT Secret
					</label>
					<div class="flex space-x-2">
						<input
							type="password"
							class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white font-mono"
							bind:value={config.jwt_secret}
							placeholder="Enter JWT secret key"
						/>
						<button
							type="button"
							class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md text-sm font-medium"
							on:click={generateNewSecret}
						>
							Generate
						</button>
					</div>
					<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
						Keep this secret secure. Changing it will invalidate all existing tokens.
					</p>
				</div>

				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
							Access Token Expiration
						</label>
						<select
							class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
							bind:value={config.access_token_expiration}
						>
							<option value="5m">5 minutes</option>
							<option value="15m">15 minutes</option>
							<option value="30m">30 minutes</option>
							<option value="1h">1 hour</option>
							<option value="2h">2 hours</option>
						</select>
					</div>

					<div>
						<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
							Refresh Token Expiration
						</label>
						<select
							class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
							bind:value={config.refresh_token_expiration}
						>
							<option value="1d">1 day</option>
							<option value="7d">7 days</option>
							<option value="30d">30 days</option>
							<option value="90d">90 days</option>
						</select>
					</div>
				</div>
			</div>
		</div>

		<!-- Cookie Configuration -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Cookie Configuration</h2>
			
			<div class="space-y-4">
				<div>
					<label class="flex items-center">
						<input
							type="checkbox"
							class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
							bind:checked={config.enable_cookie_auth}
						/>
						<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Enable Cookie Authentication</span>
					</label>
					<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
						Allow authentication using HTTP-only cookies in addition to bearer tokens
					</p>
				</div>

				{#if config.enable_cookie_auth}
					<div class="pl-6 space-y-4">
						<div>
							<label class="flex items-center">
								<input
									type="checkbox"
									class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
									bind:checked={config.cookie_http_only}
								/>
								<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">HTTP Only Cookies</span>
							</label>
						</div>

						<div>
							<label class="flex items-center">
								<input
									type="checkbox"
									class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
									bind:checked={config.cookie_secure}
								/>
								<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Secure Cookies (HTTPS only)</span>
							</label>
						</div>

						<div>
							<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
								SameSite Policy
							</label>
							<select
								class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
								bind:value={config.cookie_same_site}
							>
								<option value="Strict">Strict</option>
								<option value="Lax">Lax</option>
								<option value="None">None</option>
							</select>
						</div>
					</div>
				{/if}
			</div>
		</div>

		<!-- Multi-Factor Authentication -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Multi-Factor Authentication</h2>
			
			<div>
				<label class="flex items-center">
					<input
						type="checkbox"
						class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
						bind:checked={config.mfa_required_for_admins}
					/>
					<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Require MFA for Admin Accounts</span>
				</label>
				<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
					Force all admin accounts to enable multi-factor authentication
				</p>
			</div>
		</div>

		<!-- Password Policy -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Password Policy</h2>
			
			<div class="space-y-4">
				<div>
					<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						Minimum Password Length
					</label>
					<input
						type="number"
						min="4"
						max="128"
						class="w-32 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
						bind:value={config.password_min_length}
					/>
				</div>

				<div class="space-y-2">
					<h3 class="text-sm font-medium text-gray-700 dark:text-gray-300">Password Requirements</h3>
					
					<label class="flex items-center">
						<input
							type="checkbox"
							class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
							bind:checked={config.password_require_uppercase}
						/>
						<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Require uppercase letters (A-Z)</span>
					</label>

					<label class="flex items-center">
						<input
							type="checkbox"
							class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
							bind:checked={config.password_require_lowercase}
						/>
						<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Require lowercase letters (a-z)</span>
					</label>

					<label class="flex items-center">
						<input
							type="checkbox"
							class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
							bind:checked={config.password_require_numbers}
						/>
						<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Require numbers (0-9)</span>
					</label>

					<label class="flex items-center">
						<input
							type="checkbox"
							class="rounded border-gray-300 dark:border-gray-600 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
							bind:checked={config.password_require_symbols}
						/>
						<span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Require symbols (!@#$%^&*)</span>
					</label>
				</div>

				<!-- Password Strength Indicator -->
				<div class="mt-4">
					<div class="flex items-center justify-between mb-2">
						<span class="text-sm font-medium text-gray-700 dark:text-gray-300">Password Strength Policy</span>
						<span class="text-sm text-gray-600 dark:text-gray-400">{passwordStrength.text}</span>
					</div>
					<div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
						<div 
							class="h-2 rounded-full transition-all duration-300 {passwordStrength.color}"
							style="width: {(passwordStrength.score / 5) * 100}%"
						></div>
					</div>
				</div>
			</div>
		</div>

		<!-- Account Security -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Account Security</h2>
			
			<div class="space-y-4">
				<div>
					<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						Maximum Failed Login Attempts
					</label>
					<input
						type="number"
						min="1"
						max="20"
						class="w-32 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
						bind:value={config.max_failed_attempts}
					/>
					<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
						Number of failed attempts before account lockout
					</p>
				</div>

				<div>
					<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
						Account Lockout Duration
					</label>
					<select
						class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
						bind:value={config.lockout_duration}
					>
						<option value="5m">5 minutes</option>
						<option value="15m">15 minutes</option>
						<option value="30m">30 minutes</option>
						<option value="1h">1 hour</option>
						<option value="24h">24 hours</option>
					</select>
				</div>
			</div>
		</div>

		<!-- Security Warning -->
		{#if hasChanges()}
			<div class="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
				<div class="flex">
					<div class="flex-shrink-0">
						<svg class="h-5 w-5 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
						</svg>
					</div>
					<div class="ml-3">
						<h3 class="text-sm font-medium text-yellow-800 dark:text-yellow-200">
							Unsaved Changes
						</h3>
						<div class="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
							<p>You have unsaved changes to the authentication configuration. Make sure to save your changes before leaving this page.</p>
						</div>
					</div>
				</div>
			</div>
		{/if}
	{/if}
</div>