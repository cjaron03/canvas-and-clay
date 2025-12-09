<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth';
	import { PUBLIC_API_BASE_URL } from '$env/static/public';
	import { fade } from 'svelte/transition';

	let setupStatus = null;
	let loading = true;
	let seeding = false;
	let seedResult = null;
	let error = null;
	let confirmProduction = false;

	onMount(async () => {
		await auth.init();
		await checkSetupStatus();
	});

	async function checkSetupStatus() {
		loading = true;
		error = null;
		try {
			const response = await fetch(`${PUBLIC_API_BASE_URL}/api/setup/status`);
			if (!response.ok) {
				throw new Error('Failed to check setup status');
			}
			setupStatus = await response.json();

			// If setup not required and not viewing results, redirect
			if (!setupStatus.setup_required && !seedResult) {
				goto('/');
			}
		} catch (err) {
			error = err.message || 'Failed to connect to server';
		} finally {
			loading = false;
		}
	}

	async function seedDemoData() {
		// Check if user is logged in as admin
		if (!$auth.isAuthenticated) {
			goto('/login?redirect=/setup');
			return;
		}

		if ($auth.user?.role !== 'admin') {
			error = 'Admin access required. Please log in as an administrator.';
			return;
		}

		// Production confirmation
		if (setupStatus?.production_warning && !confirmProduction) {
			error = 'Please confirm you want to seed demo data in production.';
			return;
		}

		seeding = true;
		error = null;

		try {
			// Get CSRF token
			let csrfToken = $auth?.csrfToken;
			if (!csrfToken) {
				const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
					credentials: 'include'
				});
				if (csrfResponse.ok) {
					const csrfData = await csrfResponse.json();
					csrfToken = csrfData.csrf_token;
				}
			}

			const headers = {
				'Content-Type': 'application/json'
			};
			if (csrfToken) {
				headers['X-CSRFToken'] = csrfToken;
			}
			if (setupStatus?.production_warning) {
				headers['X-Confirm-Production'] = 'true';
			}

			const response = await fetch(`${PUBLIC_API_BASE_URL}/api/setup/seed-demo-data`, {
				method: 'POST',
				headers,
				credentials: 'include'
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.error || errorData.detail || 'Failed to seed data');
			}

			seedResult = await response.json();
		} catch (err) {
			error = err.message || 'Failed to seed demo data';
		} finally {
			seeding = false;
		}
	}
</script>

<div class="setup-container">
	<div class="setup-card">
		{#if loading}
			<div class="loading-state" in:fade>
				<div class="spinner"></div>
				<p>Checking setup status...</p>
			</div>
		{:else if seedResult?.success && !seedResult.skipped}
			<!-- Completion Screen -->
			<div class="card-header" in:fade>
				<div class="logo">Canvas & Clay</div>
				<h1>Setup Complete</h1>
			</div>

			<div class="card-body" in:fade>
				<p class="subtitle">Your Canvas & Clay instance is ready to use.</p>

				<div class="summary-section">
					<h3>Created:</h3>
					<ul class="created-list">
						<li>{seedResult.created.users} new users</li>
						<li>{seedResult.created.artists} artist</li>
						<li>{seedResult.created.artworks} artworks</li>
						<li>{seedResult.created.photos} photos</li>
					</ul>
				</div>

				<div class="warning-section">
					<h3>Important: Security Reminders</h3>
					<p>Before using this in production, please:</p>
					<ul class="warning-list">
						{#each seedResult.security_warnings as warning}
							<li>{warning}</li>
						{/each}
					</ul>
				</div>

				<div class="actions">
					<a href="/gallery" class="primary-btn">Explore Gallery</a>
				</div>
			</div>
		{:else if setupStatus?.setup_required || seedResult?.skipped}
			<!-- Welcome Screen -->
			<div class="card-header" in:fade>
				<div class="logo">Canvas & Clay</div>
				<h1>Welcome to Canvas & Clay</h1>
			</div>

			<div class="card-body" in:fade>
				{#if seedResult?.skipped}
					<div class="info-banner">
						<p>Demo data already exists in this database.</p>
					</div>
					<div class="actions">
						<a href="/gallery" class="primary-btn">Go to Gallery</a>
					</div>
				{:else}
					<p class="subtitle">
						You're almost ready to start managing your art collection.
						This setup wizard will create demo data so you can explore
						the system's features.
					</p>

					{#if setupStatus?.production_warning}
						<div class="production-warning">
							<h3>Production Mode Detected</h3>
							<p>
								You are setting up a production instance. Demo data should
								typically only be used for testing purposes.
							</p>
							<label class="checkbox-label">
								<input type="checkbox" bind:checked={confirmProduction} />
								<span>I understand and want to proceed with demo data</span>
							</label>
						</div>
					{/if}

					<div class="info-section">
						<h3>What gets created:</h3>
						<ul>
							<li>3 user accounts (admin, artist, guest)</li>
							<li>1 demo artist profile linked to artworks</li>
							<li>5 sample artworks with placeholder images</li>
							<li>1 storage location</li>
						</ul>
					</div>

					{#if !$auth.isAuthenticated}
						<div class="login-notice">
							<p>You need to be logged in as an admin to seed demo data.</p>
							<a href="/login?redirect=/setup" class="text-btn">Log in as Admin</a>
						</div>
					{:else if $auth.user?.role !== 'admin'}
						<div class="error-notice">
							<p>You are logged in as <strong>{$auth.user?.email}</strong> ({$auth.user?.role}).</p>
							<p>Admin access is required to seed demo data.</p>
						</div>
					{/if}

					{#if error}
						<div class="error-msg">{error}</div>
					{/if}

					<div class="actions">
						{#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
							<button
								class="primary-btn"
								on:click={seedDemoData}
								disabled={seeding || (setupStatus?.production_warning && !confirmProduction)}
							>
								{seeding ? 'Seeding...' : 'Seed Demo Data'}
							</button>
						{:else}
							<a href="/login?redirect=/setup" class="primary-btn">Log in to Continue</a>
						{/if}
					</div>
				{/if}
			</div>
		{:else}
			<!-- Setup not required -->
			<div class="card-header" in:fade>
				<div class="logo">Canvas & Clay</div>
				<h1>Setup Complete</h1>
			</div>
			<div class="card-body" in:fade>
				<p class="subtitle">Your instance is already set up.</p>
				<div class="actions">
					<a href="/" class="primary-btn">Go to Home</a>
				</div>
			</div>
		{/if}

		{#if error && !setupStatus?.setup_required}
			<div class="error-msg" in:fade>{error}</div>
		{/if}
	</div>

	<div class="footer">
		<div class="links">
			<a href="/help">Help</a>
			<a href="/privacy">Privacy</a>
			<a href="/terms">Terms</a>
		</div>
	</div>
</div>

<style>
	:global(body) {
		background: var(--bg-secondary);
		font-family: 'Google Sans', 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
		margin: 0;
	}

	.setup-container {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		min-height: 100vh;
		padding: 24px;
		background: var(--bg-secondary);
	}

	.setup-card {
		background: var(--bg-primary);
		width: 100%;
		max-width: 520px;
		border-radius: 12px;
		padding: 40px 40px 36px;
		box-sizing: border-box;
		box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
	}

	@media (min-width: 600px) {
		.setup-card {
			padding: 48px 48px 40px;
			box-shadow: 0 2px 6px rgba(0,0,0,0.08), 0 8px 24px rgba(0,0,0,0.06);
		}
	}

	.logo {
		font-family: 'Google Sans', 'Product Sans', sans-serif;
		font-weight: 500;
		font-size: 24px;
		margin-bottom: 8px;
		color: var(--text-primary);
		letter-spacing: -0.5px;
	}

	.card-header {
		text-align: center;
		margin-bottom: 32px;
	}

	h1 {
		font-size: 28px;
		font-weight: 400;
		color: var(--text-primary);
		margin: 0 0 12px;
		letter-spacing: -0.5px;
	}

	.subtitle {
		font-size: 16px;
		color: var(--text-secondary);
		margin: 0 0 24px;
		line-height: 1.6;
		text-align: center;
	}

	h3 {
		font-size: 14px;
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 12px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}

	.info-section, .summary-section {
		background: var(--bg-tertiary);
		border-radius: 8px;
		padding: 20px;
		margin-bottom: 24px;
	}

	.info-section ul, .summary-section ul {
		margin: 0;
		padding-left: 20px;
		color: var(--text-secondary);
	}

	.info-section li, .summary-section li {
		margin-bottom: 8px;
		line-height: 1.5;
	}

	.created-list {
		list-style: none;
		padding: 0;
	}

	.created-list li {
		padding: 8px 0;
		border-bottom: 1px solid var(--border-color);
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.created-list li:last-child {
		border-bottom: none;
	}

	.created-list li::before {
		content: '[OK]';
		color: #34a853;
		font-weight: 600;
		font-size: 12px;
	}

	.warning-section {
		background: rgba(251, 188, 4, 0.1);
		border: 1px solid rgba(251, 188, 4, 0.3);
		border-radius: 8px;
		padding: 20px;
		margin-bottom: 24px;
	}

	.warning-section h3 {
		color: #b36b00;
	}

	.warning-section p {
		color: var(--text-secondary);
		margin: 0 0 12px;
		font-size: 14px;
	}

	.warning-list {
		margin: 0;
		padding-left: 20px;
		color: var(--text-secondary);
		font-size: 14px;
	}

	.warning-list li {
		margin-bottom: 6px;
	}

	.production-warning {
		background: rgba(234, 67, 53, 0.08);
		border: 1px solid rgba(234, 67, 53, 0.3);
		border-radius: 8px;
		padding: 20px;
		margin-bottom: 24px;
	}

	.production-warning h3 {
		color: #c53929;
		margin-bottom: 8px;
	}

	.production-warning p {
		color: var(--text-secondary);
		font-size: 14px;
		margin: 0 0 16px;
	}

	.checkbox-label {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		cursor: pointer;
		font-size: 14px;
		color: var(--text-primary);
	}

	.checkbox-label input {
		margin-top: 2px;
		width: 18px;
		height: 18px;
		cursor: pointer;
	}

	.login-notice, .error-notice {
		background: var(--bg-tertiary);
		border-radius: 8px;
		padding: 16px;
		margin-bottom: 24px;
		text-align: center;
	}

	.login-notice p, .error-notice p {
		margin: 0 0 12px;
		color: var(--text-secondary);
		font-size: 14px;
	}

	.error-notice {
		background: rgba(234, 67, 53, 0.08);
	}

	.info-banner {
		background: var(--bg-tertiary);
		border-radius: 8px;
		padding: 16px;
		margin-bottom: 24px;
		text-align: center;
	}

	.info-banner p {
		margin: 0;
		color: var(--text-secondary);
	}

	.actions {
		display: flex;
		justify-content: center;
		margin-top: 28px;
	}

	.primary-btn {
		background: var(--accent-color);
		color: white;
		border: none;
		padding: 0 32px;
		height: 48px;
		border-radius: 24px;
		font-weight: 500;
		font-size: 15px;
		cursor: pointer;
		transition: all 0.15s ease;
		box-shadow: 0 1px 2px rgba(0,0,0,0.1);
		text-decoration: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
	}

	.primary-btn:hover {
		filter: brightness(1.05);
		box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
		transform: translateY(-1px);
	}

	.primary-btn:active {
		transform: translateY(0);
		box-shadow: 0 1px 2px rgba(0,0,0,0.1);
	}

	.primary-btn:disabled {
		background: var(--bg-tertiary);
		color: var(--text-secondary);
		cursor: default;
		box-shadow: none;
		transform: none;
		filter: none;
	}

	.text-btn {
		background: none;
		border: none;
		color: var(--accent-color);
		font-weight: 500;
		font-size: 14px;
		cursor: pointer;
		padding: 10px 16px;
		border-radius: 8px;
		transition: background 0.15s ease;
		text-decoration: none;
	}

	.text-btn:hover {
		background: rgba(0, 122, 255, 0.08);
	}

	.error-msg {
		color: #ea4335;
		font-size: 13px;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		margin-top: 16px;
		padding: 12px 16px;
		background: rgba(234, 67, 53, 0.08);
		border-radius: 8px;
		text-align: center;
	}

	.loading-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 40px;
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--bg-tertiary);
		border-top-color: var(--accent-color);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
		margin-bottom: 16px;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.loading-state p {
		color: var(--text-secondary);
		font-size: 14px;
		margin: 0;
	}

	.footer {
		margin-top: 32px;
		display: flex;
		justify-content: center;
		width: 100%;
		max-width: 520px;
		font-size: 12px;
		color: var(--text-secondary);
	}

	.links a {
		color: var(--text-secondary);
		text-decoration: none;
		margin: 0 12px;
		padding: 4px 0;
		transition: color 0.15s ease;
	}

	.links a:hover {
		color: var(--text-primary);
	}

	@media (prefers-color-scheme: dark) {
		.primary-btn:hover {
			box-shadow: 0 2px 12px rgba(0, 122, 255, 0.4);
		}

		.warning-section {
			background: rgba(251, 188, 4, 0.15);
		}

		.warning-section h3 {
			color: #fbbc04;
		}

		.production-warning {
			background: rgba(234, 67, 53, 0.15);
		}

		.production-warning h3 {
			color: #ea4335;
		}
	}
</style>
