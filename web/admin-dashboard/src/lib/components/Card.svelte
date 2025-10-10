<script lang="ts">
	interface Props {
		padding?: 'none' | 'sm' | 'md' | 'lg';
		shadow?: 'none' | 'sm' | 'md' | 'lg';
		border?: boolean;
		hover?: boolean;
	}
	
	let { padding = 'md', shadow = 'sm', border = true, hover = false }: Props = $props();
	
	const classes = $derived([
		'bg-white dark:bg-gray-800 rounded-lg transition-all duration-200',
		getPaddingClasses(padding),
		getShadowClasses(shadow),
		border ? 'border border-gray-200 dark:border-gray-700' : '',
		hover ? 'hover:shadow-md hover:-translate-y-0.5' : ''
	].filter(Boolean).join(' '));
	
	function getPaddingClasses(padding: string): string {
		const paddings = {
			none: '',
			sm: 'p-4',
			md: 'p-6',
			lg: 'p-8'
		};
		return paddings[padding as keyof typeof paddings] || paddings.md;
	}
	
	function getShadowClasses(shadow: string): string {
		const shadows = {
			none: '',
			sm: 'shadow-custom-sm',
			md: 'shadow-custom-md',
			lg: 'shadow-custom-lg'
		};
		return shadows[shadow as keyof typeof shadows] || shadows.sm;
	}
</script>

<div class={classes}>
	<slot />
</div>