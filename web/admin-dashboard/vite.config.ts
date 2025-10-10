import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	build: {
		// Optimize for embedded serving
		target: 'es2020',
		minify: 'esbuild',
		sourcemap: false,
		rollupOptions: {
			output: {
				// Ensure consistent file naming for Go embedding
				entryFileNames: 'assets/[name]-[hash].js',
				chunkFileNames: 'assets/[name]-[hash].js',
				assetFileNames: 'assets/[name]-[hash].[ext]'
			}
		}
	},
	server: {
		// Development server configuration
		port: 5173,
		host: true
	}
});
