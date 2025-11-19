
<script>
	import { onMount } from 'svelte';
	import '../app.css';
	import { auth } from '$lib/stores/auth';
	import { theme } from '$lib/stores/theme';
import { page } from '$app/stores';

	// Initialize auth and theme on app load
	// Don't await - let each page handle its own auth.init() to avoid race conditions
	onMount(() => {
		auth.init().catch(err => console.error('Layout auth init failed:', err));
		theme.init();
	});

	const handleLogout = async () => {
		await auth.logout();
	};

	const toggleTheme = () => {
		theme.toggle();
	};
</script>

<nav>
	<div class="nav-container">
		<div class="nav-links">
			<a href="/" class:active={$page.url.pathname === '/'}>Home</a>
			<a href="/search" class:active={$page.url.pathname === '/search'}>Search</a>
			<a href="/artworks" class:active={$page.url.pathname.startsWith('/artworks')}>Artworks</a>
			{#if $auth.isAuthenticated && $auth.user?.role === 'artist'}
				<a href="/my-artworks" class:active={$page.url.pathname.startsWith('/my-artworks')}>My Artworks</a>
			{/if}
			{#if $auth.isAuthenticated && ($auth.user?.role === 'admin' || $auth.user?.role === 'artist')}
				<a href="/uploads" class:active={$page.url.pathname === '/uploads'}>Uploads</a>
			{/if}
			{#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
				<a href="/admin/console" class:active={$page.url.pathname.startsWith('/admin/console')}>Console</a>
			{/if}
		</div>
		<div class="nav-auth">
			<button on:click={toggleTheme} class="theme-toggle" title="Toggle theme">
				{$theme === 'dark' ? 'Light' : 'Dark'}
			</button>
			{#if $auth.isAuthenticated}
				<div class="user-info">
					<span class="user-email">{$auth.user?.email}</span>
					<span class="user-role">{$auth.user?.role}</span>
				</div>
				<button on:click={handleLogout} class="logout-btn">Logout</button>
			{:else}
				<a href="/login" class="login-link">Login</a>
			{/if}
		</div>
	</div>
</nav>

<slot />

<style>
	nav {
		background: var(--bg-secondary);
		border-bottom: 1px solid var(--border-color);
		padding: 0;
		transition: background-color 0.3s ease, border-color 0.3s ease;
	}

	.nav-container {
		max-width: 1400px;
		margin: 0 auto;
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem 2rem;
	}

	.nav-links {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.nav-links a {
		padding: 0.5rem 1rem;
		color: var(--text-secondary);
		text-decoration: none;
		border-radius: 4px;
		transition: all 0.2s;
		font-size: 0.9375rem;
		font-weight: 500;
		text-transform: capitalize;
	}

	.nav-links a:hover {
		color: var(--text-primary);
		background: var(--bg-tertiary);
	}

	.nav-links a.active {
		color: var(--accent-color);
		background: var(--bg-tertiary);
	}

	.nav-auth {
		display: flex;
		align-items: center;
		gap: 1rem;
	}

	.theme-toggle {
		padding: 0.5rem 1rem;
		background: transparent;
		border: 1px solid var(--border-color);
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 500;
		color: var(--text-primary);
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		text-transform: capitalize;
	}

	.theme-toggle:hover {
		background: var(--bg-tertiary);
		border-color: var(--accent-color);
		color: var(--accent-color);
	}

	.user-info {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: 0.25rem;
		padding-right: 1rem;
		border-right: 1px solid var(--border-color);
	}

	.user-email {
		color: var(--text-primary);
		font-size: 0.875rem;
		font-weight: 500;
	}

	.user-role {
		color: var(--accent-color);
		font-size: 0.75rem;
		text-transform: capitalize;
		font-weight: 600;
	}

	.logout-btn {
		padding: 0.5rem 1rem;
		background: var(--accent-color);
		color: white;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.875rem;
		font-weight: 500;
		transition: background 0.2s;
		text-transform: capitalize;
	}

	.logout-btn:hover {
		background: var(--accent-hover);
	}

	.login-link {
		padding: 0.5rem 1rem;
		background: var(--accent-color);
		color: white;
		text-decoration: none;
		border-radius: 4px;
		font-size: 0.875rem;
		font-weight: 500;
		transition: background 0.2s;
		text-transform: capitalize;
	}

	.login-link:hover {
		background: var(--accent-hover);
	}

	@media (max-width: 768px) {
		.nav-container {
			flex-direction: column;
			gap: 1rem;
			padding: 1rem;
		}

		.nav-links {
			flex-wrap: wrap;
			justify-content: center;
		}

		.nav-auth {
			width: 100%;
			justify-content: center;
		}

		.user-info {
			border-right: none;
			border-bottom: 1px solid var(--border-color);
			padding-right: 0;
			padding-bottom: 0.5rem;
			align-items: center;
		}
	}
</style>
