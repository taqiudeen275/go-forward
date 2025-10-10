# Dashboard Routing Fixes

## Issues Fixed

### 1. `authState.get() is not a function` Error

**Problem**: Svelte stores don't have a `.get()` method. The code was trying to call `authState.get()` which doesn't exist.

**Solution**: 
- Imported `get` from `svelte/store`
- Replaced all instances of `authState.get()` with `get(authState)`
- Fixed NodeJS.Timeout type issue by using `ReturnType<typeof setTimeout>`

**Files Modified**:
- `web/admin-dashboard/src/lib/stores/auth.ts`

### 2. Base Path Routing Issues

**Problem**: The SvelteKit app was configured with `base: '/_'` in production, but navigation and API calls weren't accounting for this base path properly, causing:
- Redirects to `/login` instead of `/_/login`
- 404 errors when accessing routes without base path
- Broken navigation links

**Solution**:
- Created a navigation utility (`web/admin-dashboard/src/lib/utils/navigation.ts`) that handles base path properly
- Updated AuthAPI to use the correct base URL with `import.meta.env.BASE_URL`
- Modified all navigation components to use the new utility functions
- Fixed route detection in layout and AuthGuard components

**Files Modified**:
- `web/admin-dashboard/src/lib/utils/navigation.ts` (new file)
- `web/admin-dashboard/src/lib/stores/auth.ts`
- `web/admin-dashboard/src/routes/login/+page.svelte`
- `web/admin-dashboard/src/routes/login/mfa/+page.svelte`
- `web/admin-dashboard/src/routes/+layout.svelte`
- `web/admin-dashboard/src/lib/components/Navigation.svelte`
- `web/admin-dashboard/src/lib/components/AuthGuard.svelte`

## Key Changes

### Navigation Utility Functions

```typescript
// Navigate with proper base path handling
export function goto(path: string, options?: Parameters<typeof svelteGoto>[1])

// Get full URL with base path
export function getPath(path: string): string

// Check if current path matches (accounting for base path)
export function isCurrentPath(path: string, currentPath: string): boolean
```

### AuthAPI Base URL Fix

```typescript
private baseURL = `${import.meta.env.BASE_URL || ''}api/auth`.replace(/\/+/g, '/').replace(/\/$/, '');
```

### Route Detection Fix

```typescript
// Use route.id instead of pathname to avoid base path issues
const isLoginRoute = $derived($page.route.id?.startsWith('/login'));
```

## Testing

1. **Build the dashboard**:
   ```bash
   cd web/admin-dashboard
   npm run build
   ```

2. **Update embedded assets**:
   ```bash
   # From project root
   rm -rf internal/dashboard/embed/build
   cp -r web/admin-dashboard/build internal/dashboard/embed/
   ```

3. **Build and run server**:
   ```bash
   go build -o server.exe ./cmd/server
   ./server.exe
   ```

4. **Test routing**:
   - Visit `http://localhost:8080/_/` - should show dashboard or redirect to login
   - Visit `http://localhost:8080/_/login` - should show login page
   - All navigation should stay within `/_/` base path
   - No 404 errors for routes without base path

## Expected Behavior

- ✅ All routes work with `/_/` base path
- ✅ Login redirects stay within base path (`/_/login`, not `/login`)
- ✅ SPA routing works correctly for all pages
- ✅ No `authState.get is not a function` errors
- ✅ Navigation links use correct base path
- ✅ API calls use correct base URL

## Development Mode

The dashboard supports development mode where it can proxy to a local SvelteKit dev server:

```go
Config{
    Enabled:  true,
    BasePath: "/_",
    DevMode:  true,  // Enable dev mode
    DevURL:   "http://localhost:5173",
}
```

When `DevMode` is true, the Go server will proxy requests to the SvelteKit dev server instead of serving embedded assets.