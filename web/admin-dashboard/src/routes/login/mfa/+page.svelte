<script lang="ts">
	import { Card, Button, Input } from '$lib/components';
	import { authActions, authState, isLoading, authError, isMFAPending } from '$lib/stores/auth';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	
	// Form state
	let mfaCode = '';
	let useBackupCode = false;
	
	// Form validation
	let codeError = '';
	
	// Redirect if not in MFA pending state
	$: if (!$isMFAPending) {
		if ($authState.session) {
			goto('/');
		} else {
			goto('/login');
		}
	}
	
	onMount(() => {
		// Clear any existing errors
		authActions.clearError();
		
		// Focus on input
		const input = document.getElementById('mfa-code');
		if (input) {
			input.focus();
		}
	});
	
	function validateForm(): boolean {
		codeError = '';
		
		if (!mfaCode) {
			codeError = useBackupCode ? 'Backup code is required' : 'Verification code is required';
		} else if (!useBackupCode && !/^\d{6}$/.test(mfaCode)) {
			codeError = 'Please enter a 6-digit code';
		} else if (useBackupCode && mfaCode.length < 8) {
			codeError = 'Backup codes are at least 8 characters';
		}
		
		return !codeError;
	}
	
	async function handleSubmit() {
		if (!validateForm()) return;
		
		await authActions.verifyMFA({
			code: mfaCode,
			backupCode: useBackupCode
		});
	}
	
	function toggleBackupCode() {
		useBackupCode = !useBackupCode;
		mfaCode = '';
		codeError = '';
	}
	
	function handleCodeInput(event: Event) {
		const target = event.target as HTMLInputElement;
		let value = target.value;
		
		if (!useBackupCode) {
			// Only allow digits for TOTP codes
			value = value.replace(/\D/g, '');
			// Limit to 6 digits
			if (value.length > 6) {
				value = value.slice(0, 6);
			}
		}
		
		mfaCode = value;
		
		// Auto-submit when 6 digits are entered for TOTP
		if (!useBackupCode && value.length === 6) {
			setTimeout(() => handleSubmit(), 100);
		}
	}
	
	async function goBack() {
		await authActions.logout();
		goto('/login');
	}
</script>

<svelte:head>
	<title>Two-Factor Authentication - Go Forward Framework</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
	<div class="max-w-md w-full space-y-8">
		<!-- Header -->
		<div class="text-center">
			<div class="mx-auto w-16 h-16 bg-primary rounded-xl flex items-center justify-center mb-4">
				<span class="text-2xl">🔐</span>
			</div>
			<h2 class="text-3xl font-bold text-gray-900 dark:text-white">
				Two-Factor Authentication
			</h2>
			<p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
				{#if useBackupCode}
					Enter one of your backup codes
				{:else}
					Enter the 6-digit code from your authenticator app
				{/if}
			</p>
		</div>

		<!-- MFA Form -->
		<Card padding="lg" shadow="lg">
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-6">
				<!-- MFA Code Input -->
				<div>
					<Input
						id="mfa-code"
						type={useBackupCode ? 'text' : 'tel'}
						label={useBackupCode ? 'Backup Code' : 'Verification Code'}
						placeholder={useBackupCode ? 'Enter backup code' : '000000'}
						bind:value={mfaCode}
						oninput={handleCodeInput}
						error={codeError}
						required
						autocomplete="one-time-code"
						disabled={$isLoading}
						size="lg"
					/>
					
					{#if !useBackupCode}
						<div class="mt-2 text-center">
							<div class="inline-flex space-x-1">
								{#each Array(6) as _, i}
									<div class="w-8 h-8 border-2 border-gray-300 dark:border-gray-600 rounded text-center flex items-center justify-center text-lg font-mono
										{mfaCode.length > i ? 'border-primary bg-primary bg-opacity-10' : ''}">
										{mfaCode[i] || ''}
									</div>
								{/each}
							</div>
						</div>
					{/if}
				</div>

				<!-- Toggle Backup Code -->
				<div class="text-center">
					<button
						type="button"
						onclick={toggleBackupCode}
						class="text-sm text-primary hover:text-primary-hover"
						disabled={$isLoading}
					>
						{#if useBackupCode}
							Use authenticator app instead
						{:else}
							Use backup code instead
						{/if}
					</button>
				</div>

				<!-- Error Message -->
				{#if $authError}
					<div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-3">
						<div class="flex">
							<svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
								<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
							</svg>
							<div class="ml-3">
								<p class="text-sm text-red-800 dark:text-red-200">
									{$authError}
								</p>
							</div>
						</div>
					</div>
				{/if}

				<!-- Submit Button -->
				<Button
					type="submit"
					variant="primary"
					size="lg"
					fullWidth
					loading={$isLoading}
					disabled={$isLoading || !mfaCode}
				>
					{#if $isLoading}
						Verifying...
					{:else}
						Verify Code
					{/if}
				</Button>

				<!-- Back Button -->
				<Button
					type="button"
					variant="ghost"
					size="md"
					fullWidth
					onclick={goBack}
					disabled={$isLoading}
				>
					← Back to Login
				</Button>
			</form>
		</Card>

		<!-- Help Text -->
		<div class="text-center space-y-2">
			<p class="text-xs text-gray-500 dark:text-gray-400">
				{#if useBackupCode}
					Backup codes are one-time use only. Make sure to save your remaining codes.
				{:else}
					Open your authenticator app and enter the 6-digit code.
				{/if}
			</p>
			<p class="text-xs text-gray-500 dark:text-gray-400">
				🔒 This verification helps keep your account secure.
			</p>
		</div>
	</div>
</div>

