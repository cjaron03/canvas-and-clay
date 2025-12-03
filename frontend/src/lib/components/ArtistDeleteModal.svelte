<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  export let artistId;
  export let artistName;
  export let onSuccess;
  export let onCancel;

  let step = 'choice'; // 'choice' | 'confirm-soft' | 'confirm-hard' | 'deleting'
  let deleteType = null; // 'soft' | 'hard'
  let error = null;
  let isDeleting = false;

  const handleChoice = (type) => {
    deleteType = type;
    step = type === 'soft' ? 'confirm-soft' : 'confirm-hard';
  };

  const handleBack = () => {
    step = 'choice';
    deleteType = null;
  };

  const handleConfirm = async () => {
    isDeleting = true;
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

      // Build URL with force parameter for hard delete
      const forceParam = deleteType === 'hard' ? '?force=true' : '';
      const url = `${PUBLIC_API_BASE_URL}/api/artists/${encodeURIComponent(artistId)}${forceParam}`;

      const response = await fetch(url, {
        method: 'DELETE',
        headers: {
          'X-CSRFToken': csrfToken || '',
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      });

      if (!response.ok) {
        const contentType = response.headers.get('content-type') || '';
        let errorMessage = 'Failed to delete artist';

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
      isDeleting = false;
    }
  };
</script>

<div class="modal-backdrop" on:click={onCancel} role="button" tabindex="-1">
  <div class="modal-content" on:click|stopPropagation role="dialog" aria-modal="true">
    {#if error}
      <div class="error-banner">{error}</div>
    {/if}

    {#if step === 'choice'}
      <h2>Delete "{artistName}"?</h2>
      <p class="subtitle">Choose deletion type:</p>

      <div class="choice-buttons">
        <button
          class="btn-soft-delete"
          on:click={() => handleChoice('soft')}
          disabled={isDeleting}
        >
          <span class="label">Soft Delete</span>
          <span class="description">30-day recovery period</span>
        </button>

        <button
          class="btn-hard-delete"
          on:click={() => handleChoice('hard')}
          disabled={isDeleting}
        >
          <span class="label">Hard Delete</span>
          <span class="description">Permanent - cannot undo</span>
        </button>
      </div>

      <button class="btn-cancel" on:click={onCancel}>Cancel</button>

    {:else if step === 'confirm-soft'}
      <h2>Soft Delete Artist?</h2>
      <div class="confirmation-message">
        <p>The artist will be hidden and marked for deletion.</p>
        <p><strong>You can restore them within 30 days</strong> from the admin panel.</p>
        <p class="warning">After 30 days, the artist will be automatically deleted permanently.</p>
      </div>

      <div class="action-buttons">
        <button class="btn-back" on:click={handleBack} disabled={isDeleting}>
          Back
        </button>
        <button
          class="btn-confirm-soft"
          on:click={handleConfirm}
          disabled={isDeleting}
        >
          {isDeleting ? 'Deleting...' : 'Confirm Soft Delete'}
        </button>
      </div>

    {:else if step === 'confirm-hard'}
      <h2 class="danger-header">PERMANENTLY DELETE ARTIST?</h2>
      <div class="confirmation-message danger">
        <p class="danger-text"><strong>This action CANNOT be undone!</strong></p>
        <p>The artist and all associated artworks will be permanently deleted.</p>
        <p>There is no recovery option.</p>
      </div>

      <div class="action-buttons">
        <button class="btn-back" on:click={handleBack} disabled={isDeleting}>
          Back
        </button>
        <button
          class="btn-confirm-hard"
          on:click={handleConfirm}
          disabled={isDeleting}
        >
          {isDeleting ? 'Deleting...' : 'PERMANENTLY DELETE'}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal-content {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 2rem;
    max-width: 500px;
    width: 90%;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  }

  .error-banner {
    background: var(--error-color);
    color: white;
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  h2 {
    margin: 0 0 1rem 0;
    color: var(--text-primary);
  }

  .danger-header {
    color: var(--error-color);
  }

  .subtitle {
    margin: 0 0 1.5rem 0;
    color: var(--text-secondary);
  }

  .choice-buttons {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .btn-soft-delete,
  .btn-hard-delete {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding: 1rem;
    border: 2px solid transparent;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
    background: transparent;
    text-align: left;
  }

  .btn-soft-delete {
    background: rgba(255, 193, 7, 0.1);
    border-color: #ffc107;
  }

  .btn-soft-delete:hover:not(:disabled) {
    background: rgba(255, 193, 7, 0.2);
    transform: translateY(-2px);
  }

  .btn-hard-delete {
    background: rgba(211, 47, 47, 0.1);
    border-color: var(--error-color);
  }

  .btn-hard-delete:hover:not(:disabled) {
    background: rgba(211, 47, 47, 0.2);
    transform: translateY(-2px);
  }

  .label {
    font-size: 1.125rem;
    font-weight: bold;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
  }

  .description {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .confirmation-message {
    margin-bottom: 1.5rem;
    padding: 1rem;
    background: var(--bg-secondary);
    border-radius: 4px;
  }

  .confirmation-message.danger {
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid var(--error-color);
  }

  .confirmation-message p {
    margin: 0.5rem 0;
    color: var(--text-primary);
  }

  .warning {
    color: #ffc107;
    font-size: 0.875rem;
  }

  .danger-text {
    color: var(--error-color);
    font-size: 1.125rem;
  }

  .action-buttons {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  .btn-cancel,
  .btn-back {
    padding: 0.75rem 1.5rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn-cancel:hover:not(:disabled),
  .btn-back:hover:not(:disabled) {
    background: var(--bg-tertiary);
  }

  .btn-confirm-soft {
    padding: 0.75rem 1.5rem;
    background: #ffc107;
    color: #000;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: background 0.2s;
  }

  .btn-confirm-soft:hover:not(:disabled) {
    background: #ffb300;
  }

  .btn-confirm-hard {
    padding: 0.75rem 1.5rem;
    background: var(--error-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: background 0.2s;
  }

  .btn-confirm-hard:hover:not(:disabled) {
    background: #b71c1c;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  @media (max-width: 768px) {
    .modal-content {
      width: 95%;
      padding: 1.5rem;
    }

    .action-buttons {
      flex-direction: column;
    }
  }
</style>
