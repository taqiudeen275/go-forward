<script lang="ts">
	interface Props {
		type?: 'text' | 'email' | 'password' | 'number' | 'tel' | 'url' | 'search';
		value?: string;
		placeholder?: string;
		disabled?: boolean;
		required?: boolean;
		readonly?: boolean;
		error?: string;
		label?: string;
		hint?: string;
		id?: string;
		name?: string;
		autocomplete?: string;
		size?: 'sm' | 'md' | 'lg';
		fullWidth?: boolean;
		oninput?: (event: Event) => void;
		onchange?: (event: Event) => void;
		onfocus?: (event: Event) => void;
		onblur?: (event: Event) => void;
		onkeydown?: (event: KeyboardEvent) => void;
		onkeyup?: (event: KeyboardEvent) => void;
	}
	
	let { 
		type = 'text',
		value = $bindable(''),
		placeholder = '',
		disabled = false,
		required = false,
		readonly = false,
		error = '',
		label = '',
		hint = '',
		id = '',
		name = '',
		autocomplete = '',
		size = 'md',
		fullWidth = true,
		oninput,
		onchange,
		onfocus,
		onblur,
		onkeydown,
		onkeyup
	}: Props = $props();
	
	// Generate unique ID if not provided
	if (!id && label) {
		id = `input-${Math.random().toString(36).substr(2, 9)}`;
	}
	
	const inputClasses = $derived([
		'block rounded-md border transition-colors duration-200',
		'focus:ring-2 focus:ring-primary focus:border-primary',
		'disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed',
		'dark:bg-gray-800 dark:border-gray-600 dark:text-white dark:placeholder-gray-400',
		'dark:disabled:bg-gray-700 dark:disabled:text-gray-500',
		fullWidth ? 'w-full' : '',
		getSizeClasses(size),
		error ? 'border-red-500 focus:border-red-500 focus:ring-red-500' : 'border-gray-300',
		readonly ? 'bg-gray-50 dark:bg-gray-700' : ''
	].filter(Boolean).join(' '));
	
	function getSizeClasses(size: string): string {
		const sizes = {
			sm: 'px-3 py-1.5 text-sm',
			md: 'px-3 py-2 text-sm',
			lg: 'px-4 py-3 text-base'
		};
		return sizes[size as keyof typeof sizes] || sizes.md;
	}
</script>

<div class="space-y-1">
	{#if label}
		<label for={id} class="block text-sm font-medium text-gray-700 dark:text-gray-300">
			{label}
			{#if required}
				<span class="text-red-500">*</span>
			{/if}
		</label>
	{/if}
	
	<input
		{type}
		{id}
		{name}
		{placeholder}
		{disabled}
		{required}
		{readonly}
		{autocomplete}
		bind:value
		class={inputClasses}
		oninput={oninput}
		onchange={onchange}
		onfocus={onfocus}
		onblur={onblur}
		onkeydown={onkeydown}
		onkeyup={onkeyup}
	/>
	
	{#if hint && !error}
		<p class="text-xs text-gray-500 dark:text-gray-400">
			{hint}
		</p>
	{/if}
	
	{#if error}
		<p class="text-xs text-red-600 dark:text-red-400">
			{error}
		</p>
	{/if}
</div>