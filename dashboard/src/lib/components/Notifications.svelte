<script lang="ts">
	import { notifications, removeNotification } from '../stores';
	import { fly } from 'svelte/transition';

	function getIconForType(type: string) {
		switch (type) {
			case 'success':
				return 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z';
			case 'error':
				return 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z';
			case 'warning':
				return 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z';
			case 'info':
			default:
				return 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
		}
	}

	function getColorClasses(type: string) {
		switch (type) {
			case 'success':
				return 'bg-green-50 dark:bg-green-900 border-green-200 dark:border-green-700 text-green-800 dark:text-green-200';
			case 'error':
				return 'bg-red-50 dark:bg-red-900 border-red-200 dark:border-red-700 text-red-800 dark:text-red-200';
			case 'warning':
				return 'bg-yellow-50 dark:bg-yellow-900 border-yellow-200 dark:border-yellow-700 text-yellow-800 dark:text-yellow-200';
			case 'info':
			default:
				return 'bg-blue-50 dark:bg-blue-900 border-blue-200 dark:border-blue-700 text-blue-800 dark:text-blue-200';
		}
	}

	function getIconColor(type: string) {
		switch (type) {
			case 'success':
				return 'text-green-400 dark:text-green-300';
			case 'error':
				return 'text-red-400 dark:text-red-300';
			case 'warning':
				return 'text-yellow-400 dark:text-yellow-300';
			case 'info':
			default:
				return 'text-blue-400 dark:text-blue-300';
		}
	}
</script>

<!-- Notification container -->
<div class="fixed top-4 right-4 z-50 space-y-2 max-w-sm w-full">
	{#each $notifications as notification (notification.id)}
		<div
			class="rounded-md border p-4 shadow-lg {getColorClasses(notification.type)}"
			transition:fly={{ x: 300, duration: 300 }}
		>
			<div class="flex">
				<div class="flex-shrink-0">
					<svg
						class="h-5 w-5 {getIconColor(notification.type)}"
						fill="none"
						viewBox="0 0 24 24"
						stroke="currentColor"
					>
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d={getIconForType(notification.type)}
						/>
					</svg>
				</div>
				<div class="ml-3 flex-1">
					<p class="text-sm font-medium">
						{notification.message}
					</p>
				</div>
				<div class="ml-4 flex-shrink-0">
					<button
						type="button"
						class="inline-flex rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-transparent focus:ring-current opacity-70 hover:opacity-100"
						on:click={() => removeNotification(notification.id)}
					>
						<svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
					</button>
				</div>
			</div>
		</div>
	{/each}
</div>