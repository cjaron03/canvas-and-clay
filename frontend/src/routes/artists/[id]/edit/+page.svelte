<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { extractErrorMessage } from '$lib/utils/errorMessages';

  export let data;

  let csrfToken = '';
  let isSubmitting = false;
  let submitError = '';

  let artistFName = data.artist.artist_fname || '';
  let artistLName = data.artist.artist_lname || '';
  let artistEmail = data.artist.email || '';
  let artistSite = data.artist.artist_site || '';
  let artistBio = data.artist.artist_bio || '';
  let artistPhone = data.artist.artist_phone || '';
  const phonePattern = /^\(\d{3}\)-\d{3}-\d{4}$/;

  onMount(async () => {
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
        credentials: 'include'
      });
      if (response.ok) {
        const tokenData = await response.json();
        csrfToken = tokenData.csrf_token;
      }
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
    }
  });

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!artistFName.trim()) {
      submitError = 'First name is required';
      return;
    }

    if (!artistLName.trim()) {
      submitError = 'Last name is required';
      return;
    }

    const trimmedPhone = artistPhone.trim();
    if (trimmedPhone && !phonePattern.test(trimmedPhone)) {
      submitError = 'Phone number must use the (123)-456-7890 format';
      return;
    }

    isSubmitting = true;
    submitError = '';

    try {
      const payload = {
        artist_fname: artistFName.trim(),
        artist_lname: artistLName.trim(),
        artist_bio: artistBio.trim() || null,
        email: artistEmail.trim() || null,
        artist_site: artistSite.trim() || null,
        artist_phone: artistPhone.trim() || null
      };

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artists/${encodeURIComponent(data.artist.artist_id)}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorMessage = await extractErrorMessage(response, 'update artist');
        throw new Error(errorMessage);
      }

      goto(`/artists/${data.artist.artist_id}`);
    } catch (err) {
      submitError = err.message || 'An error occurred while updating the artist. Suggestion: Check all fields and try again.';
      isSubmitting = false;
    }
  };
</script>

<div class="container">
  <div class="header">
    <a href="/artists/{data.artist.artist_id}" class="back-link">← Back to Artist</a>
  </div>

  <div class="form-container">
    <h1>Edit Artist</h1>
    <p class="artist-id">Artist ID: <code>{data.artist.artist_id}</code></p>

    {#if submitError}
      <div class="error-message">{submitError}</div>
    {/if}

    <form on:submit={handleSubmit}>
      <div class="form-group">
        <label for="artist-fname">First Name <span class="required">*</span></label>
        <input
          id="artist-fname"
          type="text"
          bind:value={artistFName}
          placeholder="Enter first name"
          required
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="artist-lname">Last Name <span class="required">*</span></label>
        <input
          id="artist-lname"
          type="text"
          bind:value={artistLName}
          placeholder="Enter last name"
          required
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="artist-email">Email</label>
        <input
          id="artist-email"
          type="email"
          bind:value={artistEmail}
          placeholder="name@example.com"
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="artist-site">Website or Social Link</label>
        <input
          id="artist-site"
          type="url"
          bind:value={artistSite}
          placeholder="https://example.com"
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="artist-phone">Phone</label>
        <input
          id="artist-phone"
          type="tel"
          bind:value={artistPhone}
          placeholder="(123)-456-7890"
          disabled={isSubmitting}
        />
        <small>Format: (123)-456-7890</small>
      </div>

      <div class="form-group">
        <label for="artist-bio">Bio</label>
        <textarea
          id="artist-bio"
          rows="5"
          bind:value={artistBio}
          placeholder="Share a short artist bio"
          disabled={isSubmitting}
        ></textarea>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn-primary" disabled={isSubmitting || !csrfToken}>
          {isSubmitting ? 'Updating...' : 'Update Artist'}
        </button>
        <a href="/artists/{data.artist.artist_id}" class="btn-secondary">Cancel</a>
      </div>
    </form>
  </div>
</div>

<style>
  .container {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
  }

  .header {
    margin-bottom: 2rem;
  }

  .back-link {
    color: var(--accent-color);
    text-decoration: none;
    transition: color 0.2s;
  }

  .back-link:hover {
    color: var(--accent-hover);
  }

  .form-container {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
  }

  .artist-id {
    margin: 0 0 2rem 0;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .artist-id code {
    background: var(--bg-secondary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
    font-weight: bold;
  }

  .required {
    color: var(--error-color);
  }

  .form-group input,
  .form-group textarea {
    width: 100%;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 1rem;
    font-family: inherit;
  }

  .form-group input:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .form-group input:disabled,
  .form-group textarea:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .form-group small {
    display: block;
    margin-top: 0.25rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border-color);
  }

  .btn-primary {
    padding: 0.75rem 1.5rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
    font-weight: bold;
    transition: background 0.2s;
    text-decoration: none;
    display: inline-block;
  }

  .btn-primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .btn-primary:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
  }

  .btn-secondary {
    padding: 0.75rem 1.5rem;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-secondary:hover {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
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

  @media (max-width: 768px) {
    .container {
      padding: 1rem;
    }

    .form-container {
      padding: 1.5rem;
    }

    .form-actions {
      flex-direction: column;
    }

    .btn-primary,
    .btn-secondary {
      width: 100%;
      text-align: center;
    }
  }
</style>
