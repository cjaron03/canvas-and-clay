<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';

	let email = '';
	let password = '';
	let remember = false;
	let error = '';
	let success = '';
	let loading = false;

	// Initialize auth store on mount
	onMount(async () => {
		await auth.init();

		// Check for logout success message
		if ($page.url.searchParams.get('logout') === 'success') {
			success = 'Successfully logged out';
			// Clear the query parameter
			goto('/login', { replaceState: true });
		}

		// If already logged in, redirect to uploads
		const unsubscribe = auth.subscribe((state) => {
			if (state.isAuthenticated) {
				goto('/uploads');
			}
		});

		return unsubscribe;
	});

	const handleLogin = async () => {
		error = '';
		success = '';
		loading = true;

		try {
			await auth.login(email, password, remember);
			success = 'Successfully logged in. Welcome';
			loading = false;
			// Wait a moment to show success message before redirect
			setTimeout(() => {
				goto('/uploads');
			}, 1500);
		} catch (err) {
			loading = false;
			if (err.rateLimited) {
				const retryMsg = err.retryAfter ? ` Please wait ${err.retryAfter} seconds.` : '';
				error = `Rate limit exceeded: ${err.message}${retryMsg}`;
			} else if (err.message) {
				// Use the descriptive error message from the auth store
				error = err.message;
			} else {
				error = 'Login failed. Please check your credentials and try again.';
			}
		}
	};
</script>

<h1>Login</h1>

<div class="login-container">
	<form on:submit|preventDefault={handleLogin}>
		<div class="form-group">
			<label for="email">Email</label>
			<input
				id="email"
				type="email"
				bind:value={email}
				placeholder="admin@canvas-clay.local"
				required
				disabled={loading}
			/>
		</div>

		<div class="form-group">
			<label for="password">Password</label>
			<input
				id="password"
				type="password"
				bind:value={password}
				placeholder="Enter password"
				required
				disabled={loading}
			/>
		</div>

		<div class="form-group">
			<label class="checkbox-label">
				<input type="checkbox" bind:checked={remember} disabled={loading} />
				Remember me (14 days)
			</label>
		</div>

		{#if success}
			<div class="success-message">
				{success}
			</div>
		{/if}

		{#if error}
			<div class="error-message">
				{error}
			</div>
		{/if}

		<button type="submit" disabled={loading}>
			{loading ? 'Logging in...' : 'Login'}
		</button>
	</form>

	<div class="info">
		<p><strong>Default Admin Credentials:</strong></p>
		<p>Email: <code>admin@canvas-clay.local</code></p>
		<p>Password: <code>ChangeMe123</code></p>
	</div>
</div>

<style>
	.login-container {
		max-width: 400px;
		margin: 2rem auto;
		padding: 2rem;
		background: var(--bg-secondary);
		border: 1px solid var(--border-color);
		border-radius: 8px;
	}

	form {
		margin-bottom: 2rem;
	}

	.form-group {
		margin-bottom: 1.5rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
		color: var(--text-primary);
		font-weight: bold;
	}

	input[type='email'],
	input[type='password'] {
		width: 100%;
		padding: 0.75rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border-color);
		border-radius: 4px;
		color: var(--text-primary);
		font-size: 1rem;
	}

	input[type='email']:focus,
	input[type='password']:focus {
		outline: none;
		border-color: var(--accent-color);
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.checkbox-label {
		display: flex;
		align-items: center;
		font-weight: normal;
		cursor: pointer;
	}

	.checkbox-label input[type='checkbox'] {
		margin-right: 0.5rem;
		cursor: pointer;
	}

	button[type='submit'] {
		width: 100%;
		padding: 0.75rem;
		background: var(--accent-color);
		color: white;
		border: none;
		border-radius: 4px;
		font-size: 1rem;
		font-weight: bold;
		cursor: pointer;
		transition: background 0.2s;
	}

	button[type='submit']:hover:not(:disabled) {
		background: var(--accent-hover);
	}

	button[type='submit']:disabled {
		background: var(--bg-tertiary);
		color: var(--text-tertiary);
		cursor: not-allowed;
	}

	.success-message {
		padding: 1rem;
		margin-bottom: 1rem;
		background: rgba(76, 175, 80, 0.2);
		color: var(--success-color);
		border: 1px solid var(--success-color);
		border-radius: 4px;
		font-weight: bold;
	}

	.error-message {
		padding: 1rem;
		margin-bottom: 1rem;
		background: rgba(211, 47, 47, 0.2);
		color: var(--error-color);
		border: 1px solid var(--error-color);
		border-radius: 4px;
		font-weight: bold;
	}

	.info {
		padding: 1rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border-color);
		border-radius: 4px;
		margin-bottom: 1rem;
	}

	.info p {
		margin: 0.5rem 0;
		color: var(--text-primary);
	}

	.info code {
		background: var(--bg-secondary);
		padding: 0.25rem 0.5rem;
		border-radius: 3px;
		color: var(--accent-color);
		font-family: monospace;
	}
</style>
