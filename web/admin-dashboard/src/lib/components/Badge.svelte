<script lang="ts">
	interface Props {
		variant?: 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info';
		size?: 'sm' | 'md' | 'lg';
		rounded?: boolean;
		children?: any;
	}
	
	let { variant = 'default', size = 'md', rounded = false, children }: Props = $props();
	
	const classes = $derived([
		'inline-flex items-center font-medium',
		getSizeClasses(size),
		getVariantClasses(variant),
		rounded ? 'rounded-full' : 'rounded'
	].filter(Boolean).join(' '));
	
	function getSizeClasses(size: string): string {
		const sizes = {
			sm: 'px-2 py-0.5 text-xs',
			md: 'px-2.5 py-1 text-sm',
			lg: 'px-3 py-1.5 text-base'
		};
		return sizes[size as keyof typeof sizes] || sizes.md;
	}
	
	function getVariantClasses(variant: string): string {
		const variants = {
			default: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
			primary: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
			success: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
			warning: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300',
			danger: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
			info: 'bg-sky-100 text-sky-800 dark:bg-sky-900 dark:text-sky-300'
		};
		return variants[variant as keyof typeof variants] || variants.default;
	}
</script>

<span class={classes}>
	{@render children?.()}
</span>