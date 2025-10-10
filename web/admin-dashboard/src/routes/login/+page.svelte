<script lang="ts">
	import { Card, Button, Input } from '$lib/components';
	import { authActions, authState, isLoading, authError } from '$lib/stores/auth';
	import { goto, getPath } from '$lib/utils/navigation';
	import { onMount } from 'svelte';
	
	// Form state
	let email = '';
	let password = '';
	let rememberMe = false;
	let showPassword = false;
	
	// Form validation
	let emailError = '';
	let passwordError = '';
	
	// Redirect if already authenticated
	$: if ($authState.session && !$authState.mfaPending) {
		goto('/');
	}
	
	// Redirect to MFA if pending
	$: if ($authState.mfaPending) {
		goto('/login/mfa');
	}
	
	onMount(() => {
		// Clear any existing errors
		authActions.clearError();
	});
	
	function validateForm(): boolean {
		emailError = '';
		passwordError = '';
		
		if (!email) {
			emailError = 'Email is required';
		} else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
			emailError = 'Please enter a valid email address';
		}
		
		if (!password) {
			passwordError = 'Password is required';
		} else if (password.length < 8) {
			passwordError = 'Password must be at least 8 characters';
		}
		
		return !emailError && !passwordError;
	}
	
	async function handleSubmit() {
		if (!validateForm()) return;
		
		await authActions.login({
			email,
			password,
			rememberMe
		});
	}
	
	function togglePasswordVisibility() {
		showPassword = !showPassword;
	}
</script>

<svelte:head>
	<title>Admin Login - Go Forward Framework</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
	<div class="max-w-md w-full space-y-8">
		<!-- Header -->
		<div class="text-center">
			<div class="mx-auto w-16 h-16 bg-primary rounded-xl flex items-center justify-center mb-4">
				<span class="text-2xl font-bold text-white">GF</span>
			</div>
			<h2 class="text-3xl font-bold text-gray-900 dark:text-white">
				Admin Login
			</h2>
			<p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
				Sign in to your administrator account
			</p>
		</div>

		<!-- Login Form -->
		<Card padding="lg" shadow="lg">
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-6">
				<!-- Email Input -->
				<Input
					type="email"
					label="Email Address"
					placeholder="admin@example.com"
					bind:value={email}
					error={emailError}
					required
					autocomplete="email"
					disabled={$isLoading}
				/>

				<!-- Password Input -->
				<div class="relative">
					<Input
						type={showPassword ? 'text' : 'password'}
						label="Password"
						placeholder="Enter your password"
						bind:value={password}
						error={passwordError}
						required
						autocomplete="current-password"
						disabled={$isLoading}
					/>
					<button
						type="button"
						onclick={togglePasswordVisibility}
						class="absolute right-3 top-8 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
						disabled={$isLoading}
					>
						{#if showPassword}
							<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
							</svg>
						{:else}
							<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
							</svg>
						{/if}
					</button>
				</div>

				<!-- Remember Me -->
				<div class="flex items-center justify-between">
					<label class="flex items-center">
						<input
							type="checkbox"
							bind:checked={rememberMe}
							disabled={$isLoading}
							class="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded"
						/>
						<span class="ml-2 text-sm text-gray-600 dark:text-gray-400">
							Remember me
						</span>
					</label>
					
					<a
						href="{getPath('/login/forgot-password')}"
						class="text-sm text-primary hover:text-primary-hover"
					>
						Forgot password?
					</a>
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
					disabled={$isLoading}
				>
					{#if $isLoading}
						Signing in...
					{:else}
						Sign In
					{/if}
				</Button>
			</form>
		</Card>

		<!-- Security Notice -->
		<div class="text-center">
			<p class="text-xs text-gray-500 dark:text-gray-400">
				🔒 This is a secure admin area. All activities are logged and monitored.
			</p>
		</div>
	</div>
</div>