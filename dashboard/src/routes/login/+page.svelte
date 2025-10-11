<script lang="ts">
	import { api } from '$lib/api';
	import { addNotification, currentUser, currentSession } from '$lib/stores';

	let identifier = '';
	let password = '';
	let mfaCode = '';
	let loading = false;
	let showMFA = false;

	async function handleLogin() {
		if (!identifier || !password) {
			addNotification('error', 'Please enter your credentials');
			return;
		}

		loading = true;
		try {
			const response = await api.adminLogin(identifier, password, mfaCode);
			
			if (response.data) {
				currentUser.set(response.data.user);
				currentSession.set(response.data.session);
				addNotification('success', 'Login successful');
				window.location.href = '/_/';
			}
		} catch (error: any) {
			if (error.message?.includes('MFA') || error.message?.includes('verification')) {
				showMFA = true;
				addNotification('info', 'Please enter your MFA code');
			} else {
				addNotification('error', `Login failed: ${error.message || error}`);
			}
		} finally {
			loading = false;
		}
	}

	function handleKeyPress(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			handleLogin();
		}
	}
</script>

<svelte:head>
	<title>Admin Login - Go Forward</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
	<div class="max-w-md w-full space-y-8">
		<div>
			<div class="mx-auto h-12 w-12 bg-blue-600 rounded-lg flex items-center justify-center">
				<span class="text-white font-bold text-xl">GF</span>
			</div>
			<h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
				Admin Dashboard
			</h2>
			<p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
				Sign in to your admin account
			</p>
		</div>
		
		<form class="mt-8 space-y-6" on:submit|preventDefault={handleLogin}>
			<div class="space-y-4">
				<div>
					<label for="identifier" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
						Email or Username
					</label>
					<input
						id="identifier"
						name="identifier"
						type="text"
						required
						class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700"
						placeholder="Enter your email or username"
						bind:value={identifier}
						on:keypress={handleKeyPress}
					/>
				</div>
				
				<div>
					<label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
						Password
					</label>
					<input
						id="password"
						name="password"
						type="password"
						required
						class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700"
						placeholder="Enter your password"
						bind:value={password}
						on:keypress={handleKeyPress}
					/>
				</div>

				{#if showMFA}
					<div>
						<label for="mfa-code" class="block text-sm font-medium text-gray-700 dark:text-gray-300">
							MFA Code
						</label>
						<input
							id="mfa-code"
							name="mfa-code"
							type="text"
							maxlength="6"
							class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700 text-center font-mono"
							placeholder="000000"
							bind:value={mfaCode}
							on:keypress={handleKeyPress}
						/>
						<p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
							Enter the 6-digit code from your authenticator app
						</p>
					</div>
				{/if}
			</div>

			<div>
				<button
					type="submit"
					class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
					disabled={loading}
				>
					{#if loading}
						<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
							<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
							<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
						</svg>
						Signing in...
					{:else}
						Sign in
					{/if}
				</button>
			</div>

			<div class="text-center">
				<p class="text-sm text-gray-600 dark:text-gray-400">
					Need help? Contact your system administrator
				</p>
			</div>
		</form>
	</div>
</div>