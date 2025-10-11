<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';
	import { addNotification, currentUser } from '$lib/stores';

	let mfaEnabled = false;
	let loading = false;
	let showSetupModal = false;
	let showBackupCodesModal = false;
	let setupMethod: 'totp' | 'backup_codes' = 'totp';
	let qrCode = '';
	let secret = '';
	let backupCodes: string[] = [];
	let verificationCode = '';
	let setupStep = 1; // 1: method selection, 2: setup, 3: verification

	onMount(() => {
		if ($currentUser) {
			mfaEnabled = $currentUser.mfa_enabled;
		}
	});

	async function startMFASetup(method: 'totp' | 'backup_codes') {
		setupMethod = method;
		setupStep = 1;
		showSetupModal = true;

		if (method === 'totp') {
			try {
				loading = true;
				const response = await api.setupMFA('totp');
				secret = response.data?.secret || '';
				qrCode = response.data?.qr_code || '';
				setupStep = 2;
			} catch (error) {
				addNotification('error', `Failed to setup TOTP: ${error}`);
				showSetupModal = false;
			} finally {
				loading = false;
			}
		} else {
			try {
				loading = true;
				const response = await api.setupMFA('backup_codes');
				backupCodes = response.data?.backup_codes || [];
				setupStep = 2;
			} catch (error) {
				addNotification('error', `Failed to generate backup codes: ${error}`);
				showSetupModal = false;
			} finally {
				loading = false;
			}
		}
	}

	async function verifyMFASetup() {
		if (!verificationCode.trim()) {
			addNotification('error', 'Please enter the verification code');
			return;
		}

		try {
			loading = true;
			await api.verifyMFA(verificationCode);
			addNotification('success', 'MFA setup completed successfully');
			mfaEnabled = true;
			if ($currentUser) {
				$currentUser.mfa_enabled = true;
			}
			showSetupModal = false;
			resetSetupState();
		} catch (error) {
			addNotification('error', `Failed to verify MFA: ${error}`);
		} finally {
			loading = false;
		}
	}

	async function disableMFA() {
		if (!confirm('Are you sure you want to disable MFA? This will reduce your account security.')) {
			return;
		}

		try {
			loading = true;
			await api.disableMFA();
			addNotification('success', 'MFA disabled successfully');
			mfaEnabled = false;
			if ($currentUser) {
				$currentUser.mfa_enabled = false;
			}
		} catch (error) {
			addNotification('error', `Failed to disable MFA: ${error}`);
		} finally {
			loading = false;
		}
	}

	async function generateNewBackupCodes() {
		try {
			loading = true;
			const response = await api.generateBackupCodes();
			backupCodes = response.data?.backup_codes || [];
			showBackupCodesModal = true;
		} catch (error) {
			addNotification('error', `Failed to generate backup codes: ${error}`);
		} finally {
			loading = false;
		}
	}

	function resetSetupState() {
		setupStep = 1;
		verificationCode = '';
		qrCode = '';
		secret = '';
		backupCodes = [];
	}

	function downloadBackupCodes() {
		const content = backupCodes.join('\n');
		const blob = new Blob([content], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'mfa-backup-codes.txt';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	function copyBackupCodes() {
		navigator.clipboard.writeText(backupCodes.join('\n')).then(() => {
			addNotification('success', 'Backup codes copied to clipboard');
		}).catch(() => {
			addNotification('error', 'Failed to copy backup codes');
		});
	}
</script>

<svelte:head>
	<title>MFA Setup - Admin Dashboard</title>
</svelte:head>

<div class="space-y-6">
	<!-- Header -->
	<div>
		<h1 class="text-2xl font-bold text-gray-900 dark:text-white">Multi-Factor Authentication</h1>
		<p class="text-gray-600 dark:text-gray-400">Secure your account with an additional layer of protection</p>
	</div>

	<!-- MFA Status -->
	<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
		<div class="flex items-center justify-between">
			<div>
				<h2 class="text-lg font-medium text-gray-900 dark:text-white">MFA Status</h2>
				<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
					{mfaEnabled ? 'Multi-factor authentication is enabled for your account' : 'Multi-factor authentication is not enabled'}
				</p>
			</div>
			<div class="flex items-center space-x-2">
				{#if mfaEnabled}
					<span class="inline-flex px-3 py-1 text-sm font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
						Enabled
					</span>
				{:else}
					<span class="inline-flex px-3 py-1 text-sm font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
						Disabled
					</span>
				{/if}
			</div>
		</div>
	</div>

	{#if !mfaEnabled}
		<!-- Setup MFA -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Setup Multi-Factor Authentication</h2>
			<p class="text-gray-600 dark:text-gray-400 mb-6">
				Choose a method to secure your account with multi-factor authentication.
			</p>

			<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
				<!-- TOTP Setup -->
				<div class="border border-gray-200 dark:border-gray-700 rounded-lg p-6">
					<div class="flex items-center mb-4">
						<div class="h-10 w-10 bg-blue-500 rounded-lg flex items-center justify-center">
							<svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
							</svg>
						</div>
						<h3 class="ml-3 text-lg font-medium text-gray-900 dark:text-white">Authenticator App</h3>
					</div>
					<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
						Use an authenticator app like Google Authenticator, Authy, or 1Password to generate time-based codes.
					</p>
					<button
						type="button"
						class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
						disabled={loading}
						on:click={() => startMFASetup('totp')}
					>
						Setup Authenticator App
					</button>
				</div>

				<!-- Backup Codes Setup -->
				<div class="border border-gray-200 dark:border-gray-700 rounded-lg p-6">
					<div class="flex items-center mb-4">
						<div class="h-10 w-10 bg-green-500 rounded-lg flex items-center justify-center">
							<svg class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
							</svg>
						</div>
						<h3 class="ml-3 text-lg font-medium text-gray-900 dark:text-white">Backup Codes</h3>
					</div>
					<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
						Generate a set of backup codes that you can use to access your account if you lose access to your primary MFA method.
					</p>
					<button
						type="button"
						class="w-full bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
						disabled={loading}
						on:click={() => startMFASetup('backup_codes')}
					>
						Generate Backup Codes
					</button>
				</div>
			</div>
		</div>
	{:else}
		<!-- MFA Management -->
		<div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
			<h2 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Manage MFA</h2>
			
			<div class="space-y-4">
				<div class="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
					<div>
						<h3 class="text-sm font-medium text-gray-900 dark:text-white">Backup Codes</h3>
						<p class="text-sm text-gray-600 dark:text-gray-400">Generate new backup codes for emergency access</p>
					</div>
					<button
						type="button"
						class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
						disabled={loading}
						on:click={generateNewBackupCodes}
					>
						Generate New Codes
					</button>
				</div>

				<div class="flex items-center justify-between p-4 border border-red-200 dark:border-red-700 rounded-lg bg-red-50 dark:bg-red-900">
					<div>
						<h3 class="text-sm font-medium text-red-900 dark:text-red-200">Disable MFA</h3>
						<p class="text-sm text-red-700 dark:text-red-300">Remove multi-factor authentication from your account</p>
					</div>
					<button
						type="button"
						class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium disabled:opacity-50"
						disabled={loading}
						on:click={disableMFA}
					>
						Disable MFA
					</button>
				</div>
			</div>
		</div>
	{/if}

	<!-- Security Tips -->
	<div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-6">
		<h3 class="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">Security Tips</h3>
		<ul class="text-sm text-blue-700 dark:text-blue-300 space-y-1">
			<li>• Store backup codes in a secure location separate from your device</li>
			<li>• Use a reputable authenticator app for TOTP codes</li>
			<li>• Never share your MFA codes or backup codes with anyone</li>
			<li>• Regularly review and update your security settings</li>
		</ul>
	</div>
</div>

<!-- MFA Setup Modal -->
{#if showSetupModal}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showSetupModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
				<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
					{#if setupMethod === 'totp'}
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Setup Authenticator App
						</h3>
						
						{#if setupStep === 2}
							<div class="space-y-4">
								<div class="text-center">
									<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
										Scan this QR code with your authenticator app:
									</p>
									{#if qrCode}
										<div class="flex justify-center mb-4">
											<img src={qrCode} alt="QR Code" class="border border-gray-300 dark:border-gray-600 rounded" />
										</div>
									{/if}
									<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
										Or manually enter this secret key:
									</p>
									<code class="bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-sm font-mono">
										{secret}
									</code>
								</div>
								
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Enter the 6-digit code from your app:
									</label>
									<input
										type="text"
										maxlength="6"
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white text-center text-lg font-mono"
										placeholder="000000"
										bind:value={verificationCode}
									/>
								</div>
							</div>
						{/if}
					{:else if setupMethod === 'backup_codes'}
						<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
							Backup Codes Generated
						</h3>
						
						{#if setupStep === 2}
							<div class="space-y-4">
								<p class="text-sm text-gray-600 dark:text-gray-400">
									Save these backup codes in a secure location. Each code can only be used once.
								</p>
								
								<div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
									<div class="grid grid-cols-2 gap-2 font-mono text-sm">
										{#each backupCodes as code}
											<div class="text-center py-1">{code}</div>
										{/each}
									</div>
								</div>
								
								<div class="flex space-x-2">
									<button
										type="button"
										class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md text-sm font-medium"
										on:click={downloadBackupCodes}
									>
										Download
									</button>
									<button
										type="button"
										class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
										on:click={copyBackupCodes}
									>
										Copy
									</button>
								</div>
								
								<div>
									<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
										Enter one of the backup codes to verify:
									</label>
									<input
										type="text"
										class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white text-center font-mono"
										placeholder="Enter backup code"
										bind:value={verificationCode}
									/>
								</div>
							</div>
						{/if}
					{/if}
				</div>
				
				<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
					{#if setupStep === 2}
						<button
							type="button"
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
							disabled={loading || !verificationCode.trim()}
							on:click={verifyMFASetup}
						>
							{loading ? 'Verifying...' : 'Verify & Enable MFA'}
						</button>
					{/if}
					<button
						type="button"
						class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
						on:click={() => { showSetupModal = false; resetSetupState(); }}
					>
						Cancel
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Backup Codes Modal -->
{#if showBackupCodesModal}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
			<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" on:click={() => showBackupCodesModal = false}></div>

			<div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
				<div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
					<h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
						New Backup Codes
					</h3>
					
					<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
						Your new backup codes are ready. Save them in a secure location. These codes replace any previous backup codes.
					</p>
					
					<div class="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg mb-4">
						<div class="grid grid-cols-2 gap-2 font-mono text-sm">
							{#each backupCodes as code}
								<div class="text-center py-1">{code}</div>
							{/each}
						</div>
					</div>
					
					<div class="flex space-x-2">
						<button
							type="button"
							class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md text-sm font-medium"
							on:click={downloadBackupCodes}
						>
							Download
						</button>
						<button
							type="button"
							class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
							on:click={copyBackupCodes}
						>
							Copy
						</button>
					</div>
				</div>
				
				<div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
					<button
						type="button"
						class="w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:w-auto sm:text-sm"
						on:click={() => showBackupCodesModal = false}
					>
						Close
					</button>
				</div>
			</div>
		</div>
	</div>
{/if}