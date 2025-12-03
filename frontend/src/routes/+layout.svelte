
<script>
	import { onMount, onDestroy } from 'svelte';
	import '../app.css';
	import { auth } from '$lib/stores/auth';
	import { theme } from '$lib/stores/theme';
import { page } from '$app/stores';

	// Initialize auth and theme on app load
	// Don't await - let each page handle its own auth.init() to avoid race conditions
	onMount(() => {
		auth.init().catch(err => console.error('Layout auth init failed:', err));
		theme.init();
		
		// close menu when clicking outside
		clickOutsideHandler = (event) => {
			if (showUserMenu && !event.target.closest('.user-menu-container')) {
				showUserMenu = false;
			}
		};
		
		document.addEventListener('click', clickOutsideHandler);
	});

	onDestroy(() => {
		if (clickOutsideHandler) {
			document.removeEventListener('click', clickOutsideHandler);
		}
	});

	const handleLogout = async () => {
		await auth.logout();
	};

	const toggleTheme = () => {
		theme.toggle();
	};

	let showUserMenu = false;

	const toggleUserMenu = () => {
		showUserMenu = !showUserMenu;
	};

	const closeUserMenu = () => {
		showUserMenu = false;
	};

	// get first letter of email username (before @)
	$: userInitial = $auth.user?.email ? $auth.user.email.charAt(0).toUpperCase() : '?';

	let clickOutsideHandler;
</script>

<nav>
	<div class="nav-container">
		<div class="nav-links">
			<a href="/" class:active={$page.url.pathname === '/'}>
				<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
				Home
			</a>
			<a href="/artworks" class:active={$page.url.pathname.startsWith('/artworks')}>
				<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
				Artworks
			</a>
			<a href="/gallery" class:active={$page.url.pathname.startsWith('/gallery')}>
				<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
				Gallery
			</a>
			<a href="/artists" class:active={$page.url.pathname.startsWith('/artists')}>
				<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
				Artists
			</a>
			{#if $auth.isAuthenticated && ($auth.user?.role === 'artist' || $auth.user?.role === 'admin')}
				<a href="/my-artworks" class:active={$page.url.pathname.startsWith('/my-artworks')}>
					<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
					{$auth.user?.role === 'admin' ? 'All Artworks' : 'My Artworks'}
				</a>
			{/if}
			{#if $auth.isAuthenticated && ($auth.user?.role === 'admin' || $auth.user?.role === 'artist')}
				<a href="/uploads" class:active={$page.url.pathname === '/uploads'}>
					<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
					Uploads
				</a>
			{/if}
			{#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
				<a href="/admin/console" class:active={$page.url.pathname.startsWith('/admin/console')}>
					<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
					Console
				</a>
			{/if}
		</div>
		<div class="nav-auth">
			<button on:click={toggleTheme} class="theme-toggle" title="Toggle theme">
				{#if $theme === 'dark'}
					<svg class="theme-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
					</svg>
				{:else}
					<svg class="theme-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<circle cx="12" cy="12" r="5"></circle>
						<line x1="12" y1="1" x2="12" y2="3"></line>
						<line x1="12" y1="21" x2="12" y2="23"></line>
						<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
						<line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
						<line x1="1" y1="12" x2="3" y2="12"></line>
						<line x1="21" y1="12" x2="23" y2="12"></line>
						<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
						<line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
					</svg>
				{/if}
			</button>
			{#if $auth.isAuthenticated}
				<div class="user-menu-container">
					<button
						class="user-avatar"
						on:click={toggleUserMenu}
						aria-label="User menu"
					>
						{userInitial}
					</button>
					{#if showUserMenu}
						<div
							class="user-menu-dropdown"
							role="menu"
							on:click|stopPropagation
							on:keydown={(e) => {
								if (e.key === 'Escape') {
									closeUserMenu();
								}
							}}
							tabindex="-1"
						>
							<div class="user-menu-header">
								<div class="user-menu-email">{$auth.user?.email || '—'}</div>
								<div class="user-menu-role">{$auth.user?.role || '—'}</div>
							</div>
							<div class="user-menu-divider"></div>
							<a
								href="/account"
								class="user-menu-item"
								class:active={$page.url.pathname.startsWith('/account')}
								on:click={closeUserMenu}
							>
								Account
							</a>
							<div class="user-menu-divider"></div>
							<button class="user-menu-item logout-item" on:click={handleLogout}>
								Logout
							</button>
						</div>
					{/if}
				</div>
			{:else}
				<a href="/login" class="sign-in-link">
					<svg class="person-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
						<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
						<circle cx="12" cy="7" r="4"></circle>
					</svg>
					<span>Sign in</span>
				</a>
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
		display: flex;
		align-items: center;
		gap: 0.5rem;
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
		padding: 0.5rem;
		background: transparent;
		border: 1px solid var(--border-color);
		border-radius: 4px;
		cursor: pointer;
		color: var(--text-primary);
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 36px;
		height: 36px;
	}

	.theme-icon {
		width: 18px;
		height: 18px;
		color: var(--text-primary);
		transition: color 0.2s;
	}

	.theme-toggle:hover {
		background: var(--bg-tertiary);
		border-color: var(--accent-color);
		color: var(--accent-color);
	}

	.user-menu-container {
		position: relative;
	}

	.user-avatar {
		width: 40px;
		height: 40px;
		border-radius: 50%;
		background: var(--accent-color);
		color: white;
		border: 2px solid var(--border-color);
		font-size: 1.125rem;
		font-weight: 500;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		transition: all 0.2s;
		padding: 0;
		margin: 0;
	}

	.user-avatar:hover {
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
		transform: scale(1.05);
	}

	.user-avatar:focus {
		outline: 2px solid var(--accent-color);
		outline-offset: 2px;
	}

	.user-menu-dropdown {
		position: absolute;
		top: calc(100% + 8px);
		right: 0;
		background: var(--bg-secondary);
		border: 1px solid var(--border-color);
		border-radius: 8px;
		box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
		min-width: 200px;
		z-index: 1000;
		overflow: hidden;
		animation: slideDown 0.2s ease-out;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			transform: translateY(-8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.user-menu-header {
		padding: 1rem;
		border-bottom: 1px solid var(--border-color);
	}

	.user-menu-email {
		color: var(--text-primary);
		font-size: 0.9375rem;
		font-weight: 500;
		margin-bottom: 0.25rem;
		word-break: break-word;
	}

	.user-menu-role {
		color: var(--accent-color);
		font-size: 0.8125rem;
		text-transform: capitalize;
		font-weight: 600;
	}

	.user-menu-divider {
		height: 1px;
		background: var(--border-color);
		margin: 0.5rem 0;
	}

	.user-menu-item {
		display: block;
		width: 100%;
		padding: 0.75rem 1rem;
		color: var(--text-primary);
		text-decoration: none;
		font-size: 0.9375rem;
		background: transparent;
		border: none;
		text-align: left;
		cursor: pointer;
		transition: background 0.2s;
	}

	.user-menu-item:hover {
		background: var(--bg-tertiary);
	}

	.user-menu-item.active {
		background: var(--bg-tertiary);
		color: var(--accent-color);
		font-weight: 500;
	}

	.user-menu-item.logout-item {
		color: var(--error-color, #ea4335);
	}

	.user-menu-item.logout-item:hover {
		background: rgba(234, 67, 53, 0.1);
	}


	.sign-in-link {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 1rem;
		color: var(--text-secondary);
		text-decoration: none;
		border-radius: 4px;
		font-size: 0.9375rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.sign-in-link:hover {
		color: var(--text-primary);
		background: var(--bg-tertiary);
	}

	.person-icon {
		width: 18px;
		height: 18px;
		color: var(--text-secondary);
		transition: color 0.2s;
	}

	.sign-in-link:hover .person-icon {
		color: var(--text-primary);
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

		.user-menu-dropdown {
			right: auto;
			left: 50%;
			transform: translateX(-50%);
		}
	}
</style>
