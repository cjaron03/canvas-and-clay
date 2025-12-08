
<script>
	import { onMount, onDestroy } from 'svelte';
	import '../app.css';
	import { auth } from '$lib/stores/auth';
	import { theme } from '$lib/stores/theme';
	import { page } from '$app/stores';
	import AccountSwitcher from '$lib/components/AccountSwitcher.svelte';

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
								<div class="header-avatar">
									{userInitial}
								</div>
								<div class="user-details">
									<div class="user-menu-email">{$auth.user?.email || '—'}</div>
									<div class="user-menu-role">{$auth.user?.role || '—'}</div>
								</div>
								<a
									href="/account"
									class="manage-account-btn"
									on:click={closeUserMenu}
								>
									Manage your Account
								</a>
							</div>
							{#if $auth.accounts && $auth.accounts.length > 1}
								<div class="user-menu-divider"></div>
								<AccountSwitcher on:close={closeUserMenu} on:switch={closeUserMenu} />
							{/if}
							<div class="user-menu-divider"></div>
							<div class="user-menu-actions">
								{#if !$auth.accounts || $auth.accounts.length <= 1}
									<a href="/login?mode=add-account" class="user-menu-item add-account-item" on:click={closeUserMenu}>
										<svg class="add-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
											<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
											<circle cx="8.5" cy="7" r="4"></circle>
											<line x1="20" y1="8" x2="20" y2="14"></line>
											<line x1="23" y1="11" x2="17" y2="11"></line>
										</svg>
										Add another account
									</a>
								{/if}
								<button class="user-menu-item logout-item" on:click={handleLogout}>
									<svg class="logout-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
										<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
										<polyline points="16 17 21 12 16 7"></polyline>
										<line x1="21" y1="12" x2="9" y2="12"></line>
									</svg>
									Sign out of all accounts
								</button>
							</div>
							<div class="user-menu-footer">
								<a href="/privacy" class="footer-link">Privacy Policy</a>
								<span class="footer-dot">•</span>
								<a href="/terms" class="footer-link">Terms of Service</a>
							</div>
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
		padding: 0.75rem 2rem;
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
		border-radius: 50%;
		cursor: pointer;
		color: var(--text-primary);
		transition: all 0.2s;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 40px;
		height: 40px;
	}

	.theme-icon {
		width: 20px;
		height: 20px;
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
		border: 2px solid transparent;
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
		box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
		transform: scale(1.02);
	}

	.user-avatar:focus {
		outline: 2px solid var(--accent-color);
		outline-offset: 2px;
	}

	.user-menu-dropdown {
		position: absolute;
		top: calc(100% + 10px);
		right: 0;
		background: var(--bg-secondary);
		border: 1px solid var(--border-color);
		border-radius: 28px;
		box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
		width: 380px;
		z-index: 1000;
		overflow: hidden;
		animation: slideDown 0.2s cubic-bezier(0.2, 0, 0, 1);
		padding: 0;
		display: flex;
		flex-direction: column;
	}

	@keyframes slideDown {
		from {
			opacity: 0;
			transform: translateY(-10px) scale(0.98);
		}
		to {
			opacity: 1;
			transform: translateY(0) scale(1);
		}
	}

	.user-menu-header {
		padding: 20px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		text-align: center;
	}

	.header-avatar {
		width: 80px;
		height: 80px;
		border-radius: 50%;
		background: var(--accent-color);
		color: white;
		font-size: 2.5rem;
		font-weight: 500;
		display: flex;
		align-items: center;
		justify-content: center;
		margin-bottom: 4px;
	}

	.user-details {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.user-menu-email {
		color: var(--text-primary);
		font-size: 1rem;
		font-weight: 500;
		word-break: break-word;
	}

	.user-menu-role {
		color: var(--text-secondary);
		font-size: 0.875rem;
		text-transform: capitalize;
	}

	.manage-account-btn {
		margin-top: 8px;
		padding: 8px 24px;
		background: transparent;
		border: 1px solid var(--border-color);
		border-radius: 100px;
		color: var(--text-primary);
		font-size: 0.875rem;
		font-weight: 500;
		text-decoration: none;
		transition: background-color 0.2s;
	}

	.manage-account-btn:hover {
		background-color: var(--bg-tertiary);
	}

	.user-menu-divider {
		height: 1px;
		background: var(--border-color);
		margin: 0;
	}

	.user-menu-actions {
		padding: 8px;
	}

	.user-menu-item {
		display: flex;
		align-items: center;
		gap: 12px;
		width: 100%;
		padding: 12px 24px;
		color: var(--text-primary);
		text-decoration: none;
		font-size: 0.9375rem;
		background: transparent;
		border: none;
		border-radius: 0; /* List style */
		text-align: left;
		cursor: pointer;
		transition: background 0.2s;
	}

	.user-menu-item:hover {
		background: var(--bg-tertiary);
	}

	.user-menu-item.logout-item {
		color: var(--text-primary);
		/* Align left like other items */
		justify-content: flex-start;
	}
	
	.user-menu-item.logout-item:hover {
		background: var(--bg-tertiary);
	}

	.logout-icon {
		width: 20px;
		height: 20px;
		color: var(--text-secondary);
	}

	.user-menu-item.add-account-item {
		color: var(--text-primary);
	}

	.add-icon {
		width: 20px;
		height: 20px;
		color: var(--text-secondary);
	}

	.user-menu-footer {
		padding: 12px;
		background: var(--bg-tertiary);
		border-top: 1px solid var(--border-color);
		display: flex;
		justify-content: center;
		align-items: center;
		gap: 8px;
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.footer-link {
		color: var(--text-secondary);
		text-decoration: none;
	}

	.footer-link:hover {
		text-decoration: underline;
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
			width: 90vw;
			max-width: 380px;
		}
	}
</style>
