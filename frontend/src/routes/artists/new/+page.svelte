<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { extractErrorMessage } from '$lib/utils/errorMessages';

  export let data;

  let csrfToken = '';
  let isSubmitting = false;
  let submitError = '';

  let artistFName = '';
  let artistLName = '';
  let artistEmail = '';
  let artistSite = '';
  let artistBio = '';
  let artistPhone = '';
  let selectedUserId = null;
  const phonePattern = /^\(\d{3}\)-\d{3}-\d{4}$/;

  const fetchCsrfToken = async () => {
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
  };

  const ensureCsrfToken = async () => {
    if (!csrfToken) {
      await fetchCsrfToken();
    }
    return csrfToken;
  };

  onMount(() => {
    fetchCsrfToken();
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

    const token = await ensureCsrfToken();
    if (!token) {
      submitError = 'Unable to fetch CSRF token. Please refresh and try again.';
      isSubmitting = false;
      return;
    }

    try {
      const payload = {
        artist_fname: artistFName.trim(),
        artist_lname: artistLName.trim(),
        artist_bio: artistBio.trim() || null,
        email: selectedUserId ? null : (artistEmail.trim() || null),
        artist_site: artistSite.trim() || null,
        artist_phone: artistPhone.trim() || null,
        user_id: selectedUserId
      };

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artists`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': token
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorMessage = await extractErrorMessage(response, 'create artist');
        throw new Error(errorMessage);
      }

      const data = await response.json();
      const newArtistId = data?.artist?.id;
      if (newArtistId) {
        goto(`/artists/${newArtistId}`);
      } else {
        goto('/artists');
      }
    } catch (err) {
      submitError = err.message || 'An error occurred while creating the artist. Suggestion: Check all fields and try again.';
      isSubmitting = false;
    }
  };
</script>

<div class="container">
  <div class="header">
    <a href="/artists" class="back-link">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      Back to Artists
    </a>
  </div>

  <div class="form-container">
    <h1>Add Artist</h1>
    <p class="form-hint">Fill out the details below to create a new artist profile.</p>

    {#if submitError}
      <div class="error-message">{submitError}</div>
    {/if}

    <form on:submit={handleSubmit}>
      <div class="form-grid">
        <!-- Left Column: Core Info -->
        <div class="form-column">
          <div class="form-row">
            <div class="form-group half">
              <label for="artist-fname">First Name <span class="required">*</span></label>
              <div class="input-wrapper">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                <input
                  id="artist-fname"
                  type="text"
                  bind:value={artistFName}
                  placeholder="First name"
                  required
                  disabled={isSubmitting}
                />
              </div>
            </div>

            <div class="form-group half">
              <label for="artist-lname">Last Name <span class="required">*</span></label>
              <div class="input-wrapper">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                <input
                  id="artist-lname"
                  type="text"
                  bind:value={artistLName}
                  placeholder="Last name"
                  required
                  disabled={isSubmitting}
                />
              </div>
            </div>
          </div>

          <div class="form-group">
            <label for="artist-bio">Bio</label>
            <textarea
              id="artist-bio"
              rows="6"
              bind:value={artistBio}
              placeholder="Share a short artist bio"
              disabled={isSubmitting}
            ></textarea>
          </div>
        </div>

        <!-- Right Column: Contact Info -->
        <div class="form-column">
          {#if data.users && data.users.length > 0}
            <div class="form-group">
              <label for="user-link">Link to User Account</label>
              <select
                id="user-link"
                bind:value={selectedUserId}
                disabled={isSubmitting}
              >
                <option value={null}>-- No user account (enter email manually) --</option>
                {#each data.users as user}
                  <option value={user.id}>{user.email}</option>
                {/each}
              </select>
              <small>If linked, the user's email will be used as the artist's contact email</small>
            </div>
          {/if}

          {#if !selectedUserId}
            <div class="form-group">
              <label for="artist-email">Email</label>
              <div class="input-wrapper">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                <input
                  id="artist-email"
                  type="email"
                  bind:value={artistEmail}
                  placeholder="name@example.com"
                  disabled={isSubmitting}
                />
              </div>
            </div>
          {/if}

          <div class="form-group">
            <label for="artist-phone">Phone</label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg>
              <input
                id="artist-phone"
                type="tel"
                bind:value={artistPhone}
                placeholder="(123)-456-7890"
                disabled={isSubmitting}
              />
            </div>
            <small>Format: (123)-456-7890</small>
          </div>

          <div class="form-group">
            <label for="artist-site">Website</label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
              <input
                id="artist-site"
                type="text"
                bind:value={artistSite}
                placeholder="https://example.com"
                disabled={isSubmitting}
              />
            </div>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn-primary" disabled={isSubmitting}>
          {isSubmitting ? 'Creating...' : 'Create Artist'}
        </button>
        <a href="/artists" class="btn-secondary">Cancel</a>
      </div>
    </form>
  </div>
</div>

<style>
  .container {
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
  }

  .header {
    margin-bottom: 2rem;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--accent-color);
    text-decoration: none;
    transition: color 0.2s;
    font-weight: 500;
  }

  .back-link:hover {
    color: var(--accent-hover);
  }

  .form-container {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 2rem;
    border: 1px solid var(--border-color);
  }

  h1 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
  }

  .form-hint {
    margin: 0 0 2rem 0;
    color: var(--text-secondary);
    font-size: 0.95rem;
  }

  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
  }

  .form-column {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .form-row {
    display: flex;
    gap: 1rem;
  }

  .form-group.half {
    flex: 1;
  }

  .form-group {
    margin-bottom: 0;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
    font-weight: 600;
    font-size: 0.9rem;
  }

  .required {
    color: var(--error-color);
  }

  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-icon {
    position: absolute;
    left: 1rem;
    color: var(--text-secondary);
    pointer-events: none;
  }

  .form-group input,
  .form-group textarea,
  .form-group select {
    width: 100%;
    padding: 0.75rem 1rem 0.75rem 2.5rem; /* Space for icon */
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 1rem;
    font-family: inherit;
    transition: all 0.2s;
  }

  .form-group select {
    padding: 0.75rem 1rem; /* No icon space needed for select */
    cursor: pointer;
  }

  .form-group textarea {
    padding: 0.75rem; /* Reset padding for textarea (no icon) */
    resize: vertical;
  }

  .form-group input:focus,
  .form-group textarea:focus,
  .form-group select:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(90, 159, 212, 0.1);
  }

  .form-group input:disabled,
  .form-group textarea:disabled,
  .form-group select:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .form-group small {
    display: block;
    margin-top: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.8rem;
  }

  .form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border-color);
  }

  .btn-primary {
    padding: 0.75rem 2rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1rem;
    font-weight: 600;
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
    padding: 0.75rem 2rem;
    background: transparent;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: all 0.2s;
    font-weight: 500;
  }

  .btn-secondary:hover {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
  }

  .error-message {
    padding: 1rem;
    margin-bottom: 1.5rem;
    background: rgba(211, 47, 47, 0.1);
    color: var(--error-color);
    border: 1px solid var(--error-color);
    border-radius: 6px;
    font-weight: 500;
  }

  @media (max-width: 768px) {
    .container {
      padding: 1rem;
    }

    .form-grid {
      grid-template-columns: 1fr;
      gap: 1.5rem;
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
