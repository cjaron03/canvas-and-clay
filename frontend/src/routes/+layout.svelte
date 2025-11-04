
<script>
	import { onMount } from 'svelte';
	import '../app.css';
	import { auth } from '$lib/stores/auth';

	// Initialize auth on app load
	onMount(() => {
		auth.init();
	});

	const handleLogout = async () => {
		await auth.logout();
	};
</script>

<nav>
	<div class="nav-links">
		<a href="/">home</a>
		<a href="/search">search</a>
		<a href="/uploads">uploads</a>
	</div>
	<div class="nav-auth">
		{#if $auth.isAuthenticated}
			<span class="user-info">{$auth.user?.email} ({$auth.user?.role})</span>
			<button on:click={handleLogout} class="logout-btn">logout</button>
		{:else}
			<a href="/login">login</a>
		{/if}
	</div>
</nav>

<slot />

<style>
	nav {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1rem;
		background: #1e1e1e;
		border-bottom: 1px solid #444;
	}

	.nav-links {
		display: flex;
		gap: 1.5rem;
	}

	.nav-auth {
		display: flex;
		align-items: center;
		gap: 1rem;
	}

	.user-info {
		color: #999;
		font-size: 0.875rem;
	}

	.logout-btn {
		padding: 0.5rem 1rem;
		background: #5a9fd4;
		color: white;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.875rem;
		transition: background 0.2s;
	}

	.logout-btn:hover {
		background: #4a8fc4;
	}
</style>

