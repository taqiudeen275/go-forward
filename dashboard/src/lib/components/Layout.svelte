<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { currentUser, currentSession, sidebarOpen, theme, notifications } from '../stores';
	import { api } from '../api';
	import Sidebar from './Sidebar.svelte';
	import Header from './Header.svelte';
	import Notifications from './Notifications.svelte';

	let { children } = $props();

	onMount(async () => {
		// Check if user is authenticated
		try {
			const response = await api.getAdminSession();
			if (response.data) {
				currentUser.set(response.data.user);
				currentSession.set(response.data.session);
			}
		} catch (error) {
			// User not authenticated, redirect to login if not already there
			if (!$page.url.pathname.includes('/login')) {
				window.location.href = '/_/login';
			}
		}
	});
</script>

<div class="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
	<!-- Notifications -->
	<Notifications />

	{#if $currentUser}
		<!-- Authenticated layout -->
		<div class="flex h-screen">
			<!-- Sidebar -->
			<Sidebar />
			
			<!-- Main content -->
			<div class="flex-1 flex flex-col overflow-hidden">
				<!-- Header -->
				<Header />
				
				<!-- Page content -->
				<main class="flex-1 overflow-x-hidden overflow-y-auto bg-gray-50 dark:bg-gray-900 p-6">
					{@render children?.()}
				</main>
			</div>
		</div>

		<!-- Mobile sidebar overlay -->
		{#if $sidebarOpen}
			<div 
				class="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
				on:click={() => sidebarOpen.set(false)}
			></div>
		{/if}
	{:else}
		<!-- Unauthenticated layout -->
		<div class="min-h-screen flex items-center justify-center">
			{@render children?.()}
		</div>
	{/if}
</div>

<style>
	:global(html) {
		scroll-behavior: smooth;
	}
	
	:global(.dark) {
		color-scheme: dark;
	}
</style>