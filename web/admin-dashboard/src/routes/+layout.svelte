<script lang="ts">
	import '../app.css';
	import { theme } from '$lib/stores/theme';
	import { Navigation, AuthGuard } from '$lib/components';
	import { isAuthenticated } from '$lib/stores/auth';
	import { page } from '$app/stores';
	
	let { children } = $props();
	
	// Apply theme classes to document
	$effect(() => {
		if (typeof document !== 'undefined') {
			document.documentElement.className = `${$theme.modeClass} ${$theme.themeClass}`;
		}
	});
	
	// Check if current route is a login route
	const isLoginRoute = $derived($page.url.pathname.startsWith('/login'));
</script>

<svelte:head>
	<title>Admin Dashboard - Go Forward Framework</title>
	<meta name="description" content="Secure admin dashboard for Go Forward framework" />
</svelte:head>

<AuthGuard>
	<div class="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
		{#if $isAuthenticated && !isLoginRoute}
			<Navigation />
		{/if}
		
		<main class="animate-fade-in">
			{@render children?.()}
		</main>
	</div>
</AuthGuard>
