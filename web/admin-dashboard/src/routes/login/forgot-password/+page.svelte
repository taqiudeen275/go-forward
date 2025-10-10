<script lang="ts">
	import { Card, Button, Input } from '$lib/components';
	import { writable } from 'svelte/store';
	import { getPath } from '$lib/utils/navigation';
	
	// Form state
	let email = '';
	let emailError = '';
	let isLoading = false;
	let isSubmitted = false;
	let error = '';
	
	function validateEmail(): boolean {
		emailError = '';
		
		if (!email) {
			emailError = 'Email is required';
		} else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
			emailError = 'Please enter a valid email address';
		}
		
		return !emailError;
	}
	
	async function handleSubmit() {
		if (!validateEmail()) return;
		
		isLoading = true;
		error = '';
		
		try {
			// Simulate API call
			const response = await fetch('/api/admin/auth/forgot-password', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ email })
			});
			
			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.message || 'Failed to send reset email');
			}
			
			isSubmitted = true;
		} catch (err) {
			error = err instanceof Error ? err.message : 'An error occurred';
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>Forgot Password - Go Forward Framework</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
	<div class="max-w-md w-full space-y-8">
		<!-- Header -->
		<div class="text-center">
			<div class="mx-auto w-16 h-16 bg-primary rounded-xl flex items-center justify-center mb-4">
				<span class="text-2xl">🔑</span>
			</div>
			<h2 class="text-3xl font-bold text-gray-900 dark:text-white">
				Forgot Password
			</h2>
			<p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
				{#if isSubmitted}
					Check your email for reset instructions
				{:else}
					Enter your email to receive password reset instructions
				{/if}
			</p>
		</div>

		<Card padding="lg" shadow="lg">
			{#if isSubmitted}
				<!-- Success State -->
				<div class="text-center space-y-4">
					<div class="mx-auto w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center">
						<svg class="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
						</svg>
					</div>
					
					<div>
						<h3 class="text-lg font-medium text-gray-900 dark:text-white">
							Email Sent
						</h3>
						<p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
							We've sent password reset instructions to <strong>{email}</strong>
						</p>
					</div>
					
					<div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md p-4">
						<div class="flex">
							<svg class="w-5 h-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
								<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
							</svg>
							<div class="ml-3">
								<p class="text-sm text-blue-800 dark:text-blue-200">
									The email may take a few minutes to arrive. Check your spam folder if you don't see it.
								</p>
							</div>
						</div>
					</div>
					
					<div class="space-y-3">
						<Button
							variant="primary"
							size="lg"
							fullWidth
							href={getPath('/login')}
						>
							Back to Login
						</Button>
						
						<Button
							variant="ghost"
							size="md"
							fullWidth
							onclick={() => { isSubmitted = false; email = ''; }}
						>
							Try Different Email
						</Button>
					</div>
				</div>
			{:else}
				<!-- Form State -->
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
						disabled={isLoading}
					/>

					<!-- Error Message -->
					{#if error}
						<div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-3">
							<div class="flex">
								<svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
									<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
								</svg>
								<div class="ml-3">
									<p class="text-sm text-red-800 dark:text-red-200">
										{error}
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
						loading={isLoading}
						disabled={isLoading}
					>
						{#if isLoading}
							Sending Email...
						{:else}
							Send Reset Email
						{/if}
					</Button>

					<!-- Back to Login -->
					<Button
						variant="ghost"
						size="md"
						fullWidth
						href={getPath('/login')}
						disabled={isLoading}
					>
						← Back to Login
					</Button>
				</form>
			{/if}
		</Card>

		<!-- Security Notice -->
		<div class="text-center">
			<p class="text-xs text-gray-500 dark:text-gray-400">
				🔒 Password reset links expire after 1 hour for security.
			</p>
		</div>
	</div>
</div>