<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  export let artworkId;
  export let artworkTitle;
  export let onSuccess;

  let showConfirm = false;
  let isRestoring = false;
  let error = null;

  const handleRestore = async () => {
    if (!showConfirm) {
      showConfirm = true;
      return;
    }

    isRestoring = true;
    error = null;

    try {
      // Fetch CSRF token
      const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
        credentials: 'include'
      });

      let csrfToken = '';
      if (csrfResponse.ok) {
        const csrfData = await csrfResponse.json();
        csrfToken = csrfData.csrf_token;
      }

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/artworks/${encodeURIComponent(artworkId)}/restore`,
        {
          method: 'PUT',
          headers: {
            'X-CSRFToken': csrfToken || '',
            'Content-Type': 'application/json'
          },
          credentials: 'include'
        }
      );

      if (!response.ok) {
        const contentType = response.headers.get('content-type') || '';
        let errorMessage = 'Failed to restore artwork';

        if (contentType.includes('application/json')) {
          try {
            const errorData = await response.json();
            errorMessage = errorData.error || errorMessage;
          } catch {
            // JSON parsing failed
          }
        }
        throw new Error(errorMessage);
      }

      const result = await response.json();
      onSuccess(result);

    } catch (err) {
      error = err.message || 'An unexpected error occurred';
      isRestoring = false;
      showConfirm = false;
    }
  };

  const handleCancel = () => {
    showConfirm = false;
  };
</script>

{#if error}
  <div class="error">{error}</div>
{/if}

<div class="restore-container">
  {#if !showConfirm}
    <button class="btn-restore" on:click={handleRestore} disabled={isRestoring}>
      <span class="icon">↺</span> Restore Artwork
    </button>
  {:else}
    <div class="restore-confirm">
      <span class="confirm-text">Restore "{artworkTitle}"?</span>
      <button class="btn-restore-confirm" on:click={handleRestore} disabled={isRestoring}>
        {isRestoring ? 'Restoring...' : 'Confirm'}
      </button>
      <button class="btn-cancel" on:click={handleCancel} disabled={isRestoring}>
        Cancel
      </button>
    </div>
  {/if}
</div>

<style>
  .restore-container {
    display: inline-block;
  }

  .btn-restore {
    padding: 0.5rem 1rem;
    background: #4caf50;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: background 0.2s;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .btn-restore:hover:not(:disabled) {
    background: #45a049;
  }

  .icon {
    font-size: 1.25rem;
  }

  .restore-confirm {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    padding: 0.5rem 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
  }

  .confirm-text {
    color: var(--text-primary);
    font-size: 0.875rem;
    font-weight: 500;
  }

  .btn-restore-confirm {
    padding: 0.5rem 1rem;
    background: #4caf50;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: background 0.2s;
  }

  .btn-restore-confirm:hover:not(:disabled) {
    background: #45a049;
  }

  .btn-cancel {
    padding: 0.5rem 1rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn-cancel:hover:not(:disabled) {
    background: var(--bg-tertiary);
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-color);
    color: white;
    border-radius: 4px;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
  }
</style>
