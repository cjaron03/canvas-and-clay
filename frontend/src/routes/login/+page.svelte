<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth';

	let email = '';
	let password = '';
	let remember = false;
	let error = '';
	let loading = false;

	// Initialize auth store on mount
	onMount(async () => {
		await auth.init();

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
		loading = true;

		try {
			await auth.login(email, password, remember);
			// Successful login will trigger redirect via store subscription
			goto('/uploads');
		} catch (err) {
			loading = false;
			error = err.message || 'Login failed. Please try again.';
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

	<div class="security-info">
		<p><strong>Security Features:</strong></p>
		<ul>
			<li>Account lockout after 5 failed attempts (15 min)</li>
			<li>Session timeout after 30 minutes of inactivity</li>
			<li>Secure cookie-based sessions</li>
		</ul>
	</div>
</div>

<style>
	.login-container {
		max-width: 400px;
		margin: 2rem auto;
		padding: 2rem;
		background: #1e1e1e;
		border: 1px solid #444;
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
		color: #e0e0e0;
		font-weight: bold;
	}

	input[type='email'],
	input[type='password'] {
		width: 100%;
		padding: 0.75rem;
		background: #2a2a2a;
		border: 1px solid #444;
		border-radius: 4px;
		color: #e0e0e0;
		font-size: 1rem;
	}

	input[type='email']:focus,
	input[type='password']:focus {
		outline: none;
		border-color: #5a9fd4;
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
		background: #5a9fd4;
		color: white;
		border: none;
		border-radius: 4px;
		font-size: 1rem;
		font-weight: bold;
		cursor: pointer;
		transition: background 0.2s;
	}

	button[type='submit']:hover:not(:disabled) {
		background: #4a8fc4;
	}

	button[type='submit']:disabled {
		background: #444;
		color: #666;
		cursor: not-allowed;
	}

	.error-message {
		padding: 1rem;
		margin-bottom: 1rem;
		background: #3a1e1e;
		color: #d57676;
		border: 1px solid #5a2d2d;
		border-radius: 4px;
		font-weight: bold;
	}

	.info {
		padding: 1rem;
		background: #1e2a3a;
		border: 1px solid #3a4a5a;
		border-radius: 4px;
		margin-bottom: 1rem;
	}

	.info p {
		margin: 0.5rem 0;
		color: #e0e0e0;
	}

	.info code {
		background: #2a2a2a;
		padding: 0.25rem 0.5rem;
		border-radius: 3px;
		color: #5a9fd4;
		font-family: monospace;
	}

	.security-info {
		padding: 1rem;
		background: #1e3a1e;
		border: 1px solid #2d5a2d;
		border-radius: 4px;
	}

	.security-info p {
		margin: 0 0 0.5rem 0;
		color: #a8d5a8;
		font-weight: bold;
	}

	.security-info ul {
		margin: 0;
		padding-left: 1.5rem;
		color: #a8d5a8;
	}

	.security-info li {
		margin: 0.25rem 0;
	}
</style>
