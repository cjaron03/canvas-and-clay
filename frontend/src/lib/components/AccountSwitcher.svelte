<script>
	import { auth } from '$lib/stores/auth';
	import { goto } from '$app/navigation';
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	export let showAddAccount = true;

	let switching = false;
	let removing = null;

	$: accounts = $auth.accounts || [];
	$: activeAccountId = $auth.activeAccountId;

	const getInitial = (email) => {
		return email ? email.charAt(0).toUpperCase() : '?';
	};

	const handleSwitch = async (accountId) => {
		if (accountId === activeAccountId || switching) return;

		switching = true;
		try {
			await auth.switchAccount(accountId);
			dispatch('switch', { accountId });
		} catch (error) {
			console.error('Failed to switch account:', error);
		} finally {
			switching = false;
		}
	};

	const handleRemove = async (accountId, event) => {
		event.stopPropagation();
		if (removing) return;

		removing = accountId;
		try {
			await auth.removeAccount(accountId);
			dispatch('remove', { accountId });
		} catch (error) {
			console.error('Failed to remove account:', error);
		} finally {
			removing = null;
		}
	};

	const handleAddAccount = () => {
		dispatch('close');
		goto('/login?mode=add-account');
	};
</script>

{#if accounts.length > 0}
	<div class="account-switcher">
		{#if accounts.length > 1}
			<div class="section-label">Switch accounts</div>
		{/if}

		<div class="accounts-list">
			{#each accounts as account (account.id)}
				<button
					class="account-item"
					class:active={account.id === activeAccountId}
					class:switching={switching && account.id !== activeAccountId}
					on:click={() => handleSwitch(account.id)}
					disabled={switching}
				>
					<div class="account-avatar" class:active={account.id === activeAccountId}>
						{getInitial(account.email)}
					</div>
					<div class="account-info">
						<div class="account-email">{account.email}</div>
						<div class="account-role">{account.role}</div>
					</div>
					{#if account.id === activeAccountId}
						<div class="active-indicator">
							<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polyline points="20 6 9 17 4 12"></polyline>
							</svg>
						</div>
					{:else}
						<button
							class="remove-btn"
							on:click={(e) => handleRemove(account.id, e)}
							disabled={removing === account.id}
							title="Sign out of this account"
						>
							{#if removing === account.id}
								<div class="spinner"></div>
							{:else}
								<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<line x1="18" y1="6" x2="6" y2="18"></line>
									<line x1="6" y1="6" x2="18" y2="18"></line>
								</svg>
							{/if}
						</button>
					{/if}
				</button>
			{/each}
		</div>

		{#if showAddAccount && accounts.length < 5}
			<button class="add-account-btn" on:click={handleAddAccount}>
				<div class="add-icon">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<circle cx="12" cy="12" r="10"></circle>
						<line x1="12" y1="8" x2="12" y2="16"></line>
						<line x1="8" y1="12" x2="16" y2="12"></line>
					</svg>
				</div>
				<span>Add another account</span>
			</button>
		{/if}
	</div>
{/if}

<style>
	.account-switcher {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.section-label {
		padding: 8px 16px 4px;
		font-size: 0.75rem;
		font-weight: 500;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.accounts-list {
		display: flex;
		flex-direction: column;
	}

	.account-item {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 16px;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
		transition: background-color 0.15s;
		width: 100%;
	}

	.account-item:hover:not(:disabled) {
		background: var(--bg-tertiary);
	}

	.account-item:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}

	.account-item.active {
		background: var(--bg-tertiary);
	}

	.account-item.switching {
		opacity: 0.5;
	}

	.account-avatar {
		width: 36px;
		height: 36px;
		border-radius: 50%;
		background: var(--text-secondary);
		color: white;
		font-size: 1rem;
		font-weight: 500;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		transition: background-color 0.15s;
	}

	.account-avatar.active {
		background: var(--accent-color);
	}

	.account-info {
		flex: 1;
		min-width: 0;
	}

	.account-email {
		color: var(--text-primary);
		font-size: 0.875rem;
		font-weight: 500;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.account-role {
		color: var(--text-secondary);
		font-size: 0.75rem;
		text-transform: capitalize;
	}

	.active-indicator {
		color: var(--accent-color);
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.remove-btn {
		padding: 4px;
		background: transparent;
		border: none;
		border-radius: 50%;
		cursor: pointer;
		color: var(--text-secondary);
		opacity: 0;
		transition: all 0.15s;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.account-item:hover .remove-btn {
		opacity: 1;
	}

	.remove-btn:hover:not(:disabled) {
		background: var(--bg-secondary);
		color: var(--error-color, #dc3545);
	}

	.remove-btn:disabled {
		cursor: wait;
	}

	.spinner {
		width: 14px;
		height: 14px;
		border: 2px solid var(--border-color);
		border-top-color: var(--accent-color);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.add-account-btn {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 10px 16px;
		background: transparent;
		border: none;
		cursor: pointer;
		color: var(--text-primary);
		font-size: 0.875rem;
		font-weight: 500;
		transition: background-color 0.15s;
		width: 100%;
		margin-top: 4px;
	}

	.add-account-btn:hover {
		background: var(--bg-tertiary);
	}

	.add-icon {
		width: 36px;
		height: 36px;
		border-radius: 50%;
		border: 2px dashed var(--border-color);
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-secondary);
		transition: all 0.15s;
	}

	.add-account-btn:hover .add-icon {
		border-color: var(--accent-color);
		color: var(--accent-color);
	}
</style>
