<script lang="ts">
	interface Props {
		variant?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'ghost';
		size?: 'sm' | 'md' | 'lg';
		disabled?: boolean;
		loading?: boolean;
		fullWidth?: boolean;
		href?: string;
		type?: 'button' | 'submit' | 'reset';
		onclick?: () => void;
		onfocus?: () => void;
		onblur?: () => void;
	}
	
	let { 
		variant = 'primary', 
		size = 'md', 
		disabled = false, 
		loading = false, 
		fullWidth = false, 
		href = undefined, 
		type = 'button',
		onclick,
		onfocus,
		onblur
	}: Props = $props();
	
	// Compute classes based on props
	const baseClasses = $derived([
		'inline-flex items-center justify-center font-medium rounded-md transition-all duration-200',
		'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary',
		'disabled:opacity-50 disabled:cursor-not-allowed',
		fullWidth ? 'w-full' : '',
		getSizeClasses(size),
		getVariantClasses(variant)
	].filter(Boolean).join(' '));
	
	function getSizeClasses(size: string): string {
		const sizes = {
			sm: 'px-3 py-1.5 text-sm',
			md: 'px-4 py-2 text-sm',
			lg: 'px-6 py-3 text-base'
		};
		return sizes[size as keyof typeof sizes] || sizes.md;
	}
	
	function getVariantClasses(variant: string): string {
		const variants = {
			primary: 'bg-primary text-white hover:bg-primary-hover shadow-sm',
			secondary: 'bg-gray-200 text-gray-900 hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-100 dark:hover:bg-gray-600',
			success: 'bg-green-500 text-white hover:bg-green-600 shadow-sm',
			warning: 'bg-amber-500 text-white hover:bg-amber-600 shadow-sm',
			danger: 'bg-red-500 text-white hover:bg-red-600 shadow-sm',
			ghost: 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
		};
		return variants[variant as keyof typeof variants] || variants.primary;
	}
</script>

{#if href}
	<a
		{href}
		class={baseClasses}
		class:opacity-50={disabled}
		class:pointer-events-none={disabled}
		role="button"
		tabindex={disabled ? -1 : 0}
	>
		{#if loading}
			<svg class="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
			</svg>
		{/if}
		<slot />
	</a>
{:else}
	<button
		{type}
		{disabled}
		class={baseClasses}
		onclick={onclick}
		onfocus={onfocus}
		onblur={onblur}
	>
		{#if loading}
			<svg class="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
			</svg>
		{/if}
		<slot />
	</button>
{/if}