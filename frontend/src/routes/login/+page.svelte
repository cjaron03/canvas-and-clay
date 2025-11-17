<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';
	import { PUBLIC_API_BASE_URL } from '$env/static/public';

	let email = '';
	let password = '';
	let confirmPassword = '';
	let remember = false;
	let error = '';
	let success = '';
	let loading = false;
	let isRegisterMode = false;

	// Password strength + requirements (register form)
	let passwordRequirements = [];
	let strengthLabel = 'Weak';
	let strengthLevel = 0;

	// Initialize auth store on mount
	onMount(async () => {
		await auth.init();

		// Check for logout success message
		if ($page.url.searchParams.get('logout') === 'success') {
			success = 'Successfully logged out';
			// Clear the query parameter
			goto('/login', { replaceState: true });
		}

		// Check if already authenticated - redirect after a small delay
		// This only runs when the login page is actually mounted
		setTimeout(() => {
			if ($page.url.pathname === '/login' && $auth.isAuthenticated) {
				goto('/');
			}
		}, 100);
	});

	// Reactive statement: redirect to uploads if authenticated and on login page
	// This only fires when both auth state AND route change, preventing unwanted redirects
	$: if ($auth.isAuthenticated && $page.url.pathname === '/login') {
		goto('/uploads');
	}

	const handleLogin = async () => {
		error = '';
		success = '';
		loading = true;

		try {
			await auth.login(email, password, remember);
			success = 'Successfully logged in. Welcome';
			loading = false;
			// Redirect immediately after successful login
			goto('/');
		} catch (err) {
			loading = false;
			if (err.rateLimited) {
				const retryMsg = err.retryAfter ? ` Please wait ${err.retryAfter} seconds.` : '';
				error = `Rate limit exceeded: ${err.message}${retryMsg}`;
			} else if (err.message) {
				error = err.message;
			} else {
				error = 'Login failed. Please check your credentials and try again.';
			}
		}
	};

	const handleRegister = async () => {
		error = '';
		success = '';
		loading = true;

		// Validate password match
		if (password !== confirmPassword) {
			error = 'Passwords do not match';
			loading = false;
			return;
		}

		// Get CSRF token
		let csrfToken;
		try {
			const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
				credentials: 'include'
			});
			if (csrfResponse.ok) {
				const csrfData = await csrfResponse.json();
				csrfToken = csrfData.csrf_token;
			}
		} catch (err) {
			error = 'Failed to connect to server. Please try again.';
			loading = false;
			return;
		}

		try {
			const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/register`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': csrfToken || ''
				},
				credentials: 'include',
				body: JSON.stringify({ email, password })
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.error || 'Registration failed');
			}

			const data = await response.json();
			success = 'Account created successfully! You can now log in.';
			loading = false;
			
			// Switch to login mode after successful registration
			setTimeout(() => {
				isRegisterMode = false;
				password = '';
				confirmPassword = '';
			}, 2000);
		} catch (err) {
			loading = false;
			if (err.message) {
				error = err.message;
			} else {
				error = 'Registration failed. Please try again.';
			}
		}
	};

	const toggleMode = () => {
		isRegisterMode = !isRegisterMode;
		error = '';
		success = '';
		password = '';
		confirmPassword = '';
	};

	$: passwordRequirements = [
		{
			key: 'length',
			label: 'At least 8 characters',
			met: password.length >= 8,
			required: true
		},
		{
			key: 'upper',
			label: 'One uppercase letter',
			met: /[A-Z]/.test(password),
			required: true
		},
		{
			key: 'lower',
			label: 'One lowercase letter',
			met: /[a-z]/.test(password),
			required: true
		},
		{
			key: 'digit',
			label: 'One number',
			met: /\d/.test(password),
			required: true
		},
		{
			key: 'symbol',
			label: 'Add a symbol (recommended)',
			met: /[^A-Za-z0-9]/.test(password),
			required: false
		}
	];

	$: {
		const requiredMet = passwordRequirements.filter((r) => r.required && r.met).length;
		const optionalMet = passwordRequirements.filter((r) => !r.required && r.met).length;
		const lengthBonus = password.length >= 12 ? 1 : 0;

		// Simple strength score: requireds + optional + bonus
		const score = requiredMet + optionalMet + lengthBonus;
		strengthLevel = Math.max(0, Math.min(4, score));

		if (score <= 1) strengthLabel = 'Weak';
		else if (score === 2) strengthLabel = 'Okay';
		else if (score === 3) strengthLabel = 'Good';
		else strengthLabel = 'Strong';
	}
</script>

<div class="login-page">
	<div class="login-card">
		<div class="logo-section">
			<h1>Canvas and Clay</h1>
		</div>

		<div class="tabs">
			<button
				class="tab"
				class:active={!isRegisterMode}
				on:click={toggleMode}
				disabled={loading}
			>
				Sign in
			</button>
			<button
				class="tab"
				class:active={isRegisterMode}
				on:click={toggleMode}
				disabled={loading}
			>
				Create account
			</button>
		</div>

		{#if isRegisterMode}
			<form on:submit|preventDefault={handleRegister} class="auth-form">
				<div class="form-group">
					<input
						id="register-email"
						type="email"
						bind:value={email}
						placeholder="Email"
						required
						disabled={loading}
						autocomplete="email"
					/>
				</div>

				<div class="form-group">
					<input
					id="register-password"
					type="password"
					bind:value={password}
					placeholder="Password"
					required
					disabled={loading}
					autocomplete="new-password"
				/>
					<div class="password-hint">Use 8 or more characters with a mix of letters, numbers & symbols</div>
					<div class="password-strength">
						<div class="strength-label">Password strength: <span class={`pill pill-${strengthLabel.toLowerCase()}`}>{strengthLabel}</span></div>
						<div class="strength-bars">
							{#each Array(4) as _, index}
								<div class:active={index < strengthLevel}></div>
							{/each}
						</div>
					</div>
					<div class="password-requirements">
						{#each passwordRequirements as req}
							<div class={`requirement ${req.met ? 'met' : 'missing'} ${req.required ? '' : 'optional'}`}>
								<span class="icon">{req.met ? '✓' : '✕'}</span>
								<span>{req.label}{!req.required ? ' (optional)' : ''}</span>
							</div>
						{/each}
					</div>
				</div>

				<div class="form-group">
					<input
						id="confirm-password"
						type="password"
						bind:value={confirmPassword}
						placeholder="Confirm password"
						required
						disabled={loading}
						autocomplete="new-password"
					/>
				</div>

				{#if success}
					<div class="message success">
						{success}
					</div>
				{/if}

				{#if error}
					<div class="message error">
						{error}
					</div>
				{/if}

				<div class="form-actions">
					<button type="submit" class="primary-button" disabled={loading}>
						{loading ? 'Creating account...' : 'Create account'}
					</button>
				</div>
			</form>
		{:else}
			<form on:submit|preventDefault={handleLogin} class="auth-form">
				<div class="form-group">
					<input
						id="login-email"
						type="email"
						bind:value={email}
						placeholder="Email"
						required
						disabled={loading}
						autocomplete="email"
					/>
				</div>

				<div class="form-group">
					<input
						id="login-password"
						type="password"
						bind:value={password}
						placeholder="Password"
						required
						disabled={loading}
						autocomplete="current-password"
					/>
				</div>

				<div class="form-options">
					<label class="checkbox-label">
						<input type="checkbox" bind:checked={remember} disabled={loading} />
						<span>Remember me</span>
					</label>
				</div>

				{#if success}
					<div class="message success">
						{success}
					</div>
				{/if}

				{#if error}
					<div class="message error">
						{error}
					</div>
				{/if}

				<div class="form-actions">
					<button type="submit" class="primary-button" disabled={loading}>
						{loading ? 'Signing in...' : 'Sign in'}
					</button>
				</div>
			</form>
		{/if}
	</div>
</div>

<style>
	:global(body) {
		margin: 0;
		padding: 0;
	}

	.login-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
		background: var(--bg-primary);
		margin: 0;
		width: 100%;
		box-sizing: border-box;
	}

	.login-card {
		width: 100%;
		max-width: 450px;
		background: var(--bg-secondary);
		border-radius: 8px;
		padding: 3rem 2.5rem;
		box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
	}

	.logo-section {
		text-align: center;
		margin-bottom: 2rem;
	}

	.logo-section h1 {
		font-size: 1.5rem;
		font-weight: 400;
		color: var(--text-primary);
		margin: 0;
		letter-spacing: -0.5px;
	}

	.tabs {
		display: flex;
		border-bottom: 1px solid var(--border-color);
		margin-bottom: 2rem;
	}

	.tab {
		flex: 1;
		padding: 0.75rem 1rem;
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		color: var(--text-secondary);
		font-size: 0.875rem;
		cursor: pointer;
		transition: all 0.2s;
	}

	.tab:hover:not(:disabled) {
		color: var(--text-primary);
		background: rgba(0, 0, 0, 0.02);
	}

	.tab.active {
		color: var(--accent-color);
		border-bottom-color: var(--accent-color);
		font-weight: 500;
	}

	.tab:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.auth-form {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	input[type='email'],
	input[type='password'] {
		width: 100%;
		padding: 0.875rem 1rem;
		background: var(--bg-primary);
		border: 1px solid var(--border-color);
		border-radius: 4px;
		color: var(--text-primary);
		font-size: 1rem;
		transition: all 0.2s;
		box-sizing: border-box;
	}

	input[type='email']:focus,
	input[type='password']:focus {
		outline: none;
		border-color: var(--accent-color);
		box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
	}

	input:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.password-hint {
		font-size: 0.75rem;
		color: var(--text-secondary);
		margin-top: 0.25rem;
	}

	.form-options {
		display: flex;
		align-items: center;
		margin-top: -0.5rem;
	}

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		font-size: 0.875rem;
		color: var(--text-primary);
	}

	.checkbox-label input[type='checkbox'] {
		width: 1rem;
		height: 1rem;
		cursor: pointer;
	}

	.message {
		padding: 0.75rem 1rem;
		border-radius: 4px;
		font-size: 0.875rem;
		line-height: 1.4;
	}

	.message.success {
		background: rgba(52, 168, 83, 0.1);
		color: #137333;
		border: 1px solid rgba(52, 168, 83, 0.3);
	}

	.message.error {
		background: rgba(234, 67, 53, 0.1);
		color: #c5221f;
		border: 1px solid rgba(234, 67, 53, 0.3);
	}

	.password-strength {
		margin-top: 0.75rem;
	}

	.strength-label {
		color: var(--text-secondary);
		font-size: 0.95rem;
		margin-bottom: 0.35rem;
	}

	.strength-label .pill {
		margin-left: 0.35rem;
		text-transform: capitalize;
	}

	.strength-bars {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 6px;
	}

	.strength-bars div {
		height: 6px;
		background: var(--bg-tertiary);
		border-radius: 4px;
		transition: background 0.2s ease, box-shadow 0.2s ease;
	}

	.strength-bars div.active {
		background: linear-gradient(90deg, #4285f4, #34a853);
		box-shadow: 0 0 0 1px rgba(52, 168, 83, 0.15);
	}

	.password-requirements {
		margin-top: 0.65rem;
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
		gap: 0.4rem 0.75rem;
	}

	.requirement {
		display: flex;
		align-items: center;
		gap: 0.45rem;
		font-size: 0.95rem;
		color: var(--text-secondary);
	}

	.requirement .icon {
		width: 18px;
		height: 18px;
		border-radius: 50%;
		border: 1px solid var(--border-color);
		display: inline-flex;
		align-items: center;
		justify-content: center;
		font-size: 0.8rem;
	}

	.requirement.met .icon {
		background: rgba(52, 168, 83, 0.12);
		border-color: rgba(52, 168, 83, 0.4);
		color: #2c8c46;
	}

	.requirement.missing .icon {
		background: rgba(211, 47, 47, 0.08);
		border-color: rgba(211, 47, 47, 0.4);
		color: #c53030;
	}

	.requirement.optional {
		font-style: italic;
	}

	.pill {
		display: inline-block;
		padding: 0.15rem 0.65rem;
		border-radius: 999px;
		background: var(--bg-tertiary);
		border: 1px solid var(--border-color);
		font-size: 0.9rem;
		color: var(--text-primary);
	}

	.pill-weak {
		background: rgba(211, 47, 47, 0.12);
		border-color: rgba(211, 47, 47, 0.35);
		color: #c53030;
	}

	.pill-okay {
		background: rgba(251, 191, 36, 0.16);
		border-color: rgba(251, 191, 36, 0.4);
		color: #b45309;
	}

	.pill-good {
		background: rgba(66, 133, 244, 0.12);
		border-color: rgba(66, 133, 244, 0.35);
		color: #1a73e8;
	}

	.pill-strong {
		background: rgba(52, 168, 83, 0.14);
		border-color: rgba(52, 168, 83, 0.4);
		color: #2c8c46;
	}

	.form-actions {
		display: flex;
		justify-content: flex-end;
		align-items: center;
		margin-top: 0.5rem;
	}

	.primary-button {
		padding: 0.75rem 1.5rem;
		background: var(--accent-color);
		color: white;
		border: none;
		border-radius: 4px;
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
	}

	.primary-button:hover:not(:disabled) {
		background: var(--accent-hover);
		box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
	}

	.primary-button:active:not(:disabled) {
		box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
	}

	.primary-button:disabled {
		background: var(--bg-tertiary);
		color: var(--text-tertiary);
		cursor: not-allowed;
		box-shadow: none;
	}

	@media (max-width: 600px) {
		.login-card {
			padding: 2rem 1.5rem;
		}

		.form-actions {
			justify-content: stretch;
		}

		.primary-button {
			width: 100%;
		}
	}
</style>
