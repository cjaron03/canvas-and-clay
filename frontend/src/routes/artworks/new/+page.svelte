<script>
  import { onMount } from 'svelte';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { goto } from '$app/navigation';
  import { extractErrorMessage } from '$lib/utils/errorMessages';
  import { auth } from '$lib/stores/auth';

  export let data;

  let csrfToken = '';
  let isSubmitting = false;
  let submitError = '';

  // Form fields
  let title = '';
  let artistId = '';
  let storageId = '';
  let medium = '';
  let dateCreated = '';
  let artworkSize = '';

  // Searchable dropdowns
  let artistSearch = '';
  let showArtistDropdown = false;
  let storageSearch = '';
  let showStorageDropdown = false;

  // Check if logged-in user is an artist with linked profile
  $: isArtist = $auth.user?.role === 'artist';
  $: linkedArtist = $auth.user?.artist;

  // Auto-fill artist for logged-in artists
  $: if (linkedArtist && isArtist) {
    artistId = linkedArtist.id;
    artistSearch = `${linkedArtist.id} - ${linkedArtist.name}`;
  }

  onMount(async () => {
    // Fetch CSRF token
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

  // Filter artists based on search
  $: filteredArtists = artistSearch.trim()
    ? data.artists.filter(artist => {
        const searchLower = artistSearch.toLowerCase();
        return (
          artist.id.toLowerCase().includes(searchLower) ||
          artist.name.toLowerCase().includes(searchLower)
        );
      })
    : data.artists;

  // Filter storage based on search
  $: filteredStorage = storageSearch.trim()
    ? data.storage.filter(storage => {
        const searchLower = storageSearch.toLowerCase();
        return (
          storage.id.toLowerCase().includes(searchLower) ||
          storage.location.toLowerCase().includes(searchLower) ||
          (storage.type && storage.type.toLowerCase().includes(searchLower))
        );
      })
    : data.storage;

  // Select artist from dropdown
  const selectArtist = (artist) => {
    artistId = artist.id;
    artistSearch = `${artist.id} - ${artist.name}`;
    showArtistDropdown = false;
  };

  // Select storage from dropdown
  const selectStorage = (storage) => {
    storageId = storage.id;
    storageSearch = `${storage.id} - ${storage.location}${storage.type ? ` (${storage.type})` : ''}`;
    showStorageDropdown = false;
  };

  // Handle artist search input
  const handleArtistSearch = (event) => {
    artistSearch = event.target.value;
    showArtistDropdown = artistSearch.length > 0;
    // Clear selection if search doesn't match
    if (artistId && !data.artists.find(a => a.id === artistId)) {
      artistId = '';
    }
  };

  // Handle storage search input
  const handleStorageSearch = (event) => {
    storageSearch = event.target.value;
    showStorageDropdown = storageSearch.length > 0;
    // Clear selection if search doesn't match
    if (storageId && !data.storage.find(s => s.id === storageId)) {
      storageId = '';
    }
  };

  // Handle form submission
  const handleSubmit = async (event) => {
    event.preventDefault();
    
    if (!title.trim()) {
      submitError = 'Title is required';
      return;
    }
    
    if (!artistId.trim()) {
      submitError = 'Artist is required';
      return;
    }
    
    if (!storageId.trim()) {
      submitError = 'Storage location is required';
      return;
    }

    isSubmitting = true;
    submitError = '';

    try {
      const payload = {
        title: title.trim(),
        artist_id: artistId.trim(),
        storage_id: storageId.trim()
      };

      if (medium.trim()) {
        payload.medium = medium.trim();
      }
      if (dateCreated) {
        payload.date_created = dateCreated;
      }
      if (artworkSize.trim()) {
        payload.artwork_size = artworkSize.trim();
      }

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorMessage = await extractErrorMessage(response, 'create artwork');
        throw new Error(errorMessage);
      }

      const result = await response.json();
      // Redirect to the new artwork's detail page
      goto(`/artworks/${result.artwork.id}`);
    } catch (err) {
      submitError = err.message || 'An error occurred while creating the artwork. Suggestion: Check all fields and try again.';
      isSubmitting = false;
    }
  };
</script>

<div class="container">
  <div class="header">
    <a href="/artworks" class="back-link">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      Back to Artworks
    </a>
  </div>

  <div class="form-container">
    <h1>Add New Artwork</h1>

    {#if data.error}
      <div class="error-message">{data.error}</div>
    {/if}

    {#if submitError}
      <div class="error-message">{submitError}</div>
    {/if}

    <form on:submit={handleSubmit}>
      <div class="form-grid">
        <!-- Left Column: Core Info -->
        <div class="form-column">
          <div class="form-group">
            <label for="title">Title <span class="required">*</span></label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
              <input
                id="title"
                type="text"
                bind:value={title}
                placeholder="Enter artwork title"
                required
                disabled={isSubmitting}
              />
            </div>
          </div>

          <div class="form-group artwork-selector">
            <label for="artist-search">Artist <span class="required">*</span></label>
            <div class="search-wrapper">
              {#if isArtist && linkedArtist}
                <div class="artist-display-card">
                  <div class="artist-info">
                    <span class="artist-name">{linkedArtist.name}</span>
                    <span class="artist-id-badge">#{linkedArtist.id}</span>
                  </div>
                  <div class="artist-status">
                    <span class="status-text">Linked Profile</span>
                  </div>
                </div>
              {:else}
                <div class="input-wrapper">
                  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                  <input
                    id="artist-search"
                    type="text"
                    bind:value={artistSearch}
                    on:input={handleArtistSearch}
                    on:focus={() => { if (artistSearch.length > 0) showArtistDropdown = true; }}
                    placeholder="Search by ID or name..."
                    autocomplete="off"
                    disabled={isSubmitting}
                    required
                  />
                </div>
                {#if showArtistDropdown && filteredArtists.length > 0}
                  <div class="dropdown">
                    {#each filteredArtists.slice(0, 10) as artist}
                      <button
                        type="button"
                        class="dropdown-item"
                        on:click={() => selectArtist(artist)}
                      >
                        <div class="option-content">
                          <div class="option-id"><code>{artist.id}</code></div>
                          <div class="option-name">{artist.name}</div>
                        </div>
                      </button>
                    {/each}
                  </div>
                {/if}
              {/if}
            </div>
            <input type="hidden" bind:value={artistId} required />
            {#if isArtist && linkedArtist}
              <small>Artworks will be automatically associated with your artist profile.</small>
            {:else if !data.artists.length}
              <small>No artists available. Please contact an administrator.</small>
            {:else if artistId && !data.artists.find(a => a.id === artistId)}
              <small class="warning">⚠ This artist ID was not found in the list above</small>
            {:else}
              <small>Search and select an artist from the dropdown</small>
            {/if}
          </div>

          <div class="form-group artwork-selector">
            <label for="storage-search">Storage Location <span class="required">*</span></label>
            <div class="search-wrapper">
              <div class="input-wrapper">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                <input
                  id="storage-search"
                  type="text"
                  bind:value={storageSearch}
                  on:input={handleStorageSearch}
                  on:focus={() => { if (storageSearch.length > 0) showStorageDropdown = true; }}
                  placeholder="Search by ID or location..."
                  autocomplete="off"
                  required
                  disabled={isSubmitting}
                />
              </div>
              {#if showStorageDropdown && filteredStorage.length > 0}
                <div class="dropdown">
                  {#each filteredStorage.slice(0, 10) as storage}
                    <button
                      type="button"
                      class="dropdown-item"
                      on:click={() => selectStorage(storage)}
                    >
                      <div class="option-content">
                        <div class="option-id"><code>{storage.id}</code></div>
                        <div class="option-name">{storage.location}{storage.type ? ` (${storage.type})` : ''}</div>
                      </div>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
            <input type="hidden" bind:value={storageId} required />
            {#if storageId && !data.storage.find(s => s.id === storageId)}
              <small class="warning">⚠ This storage ID was not found in the list above</small>
            {/if}
          </div>
        </div>

        <!-- Right Column: Details -->
        <div class="form-column">
          <div class="form-group">
            <label for="medium">Medium</label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="4"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
              <input
                id="medium"
                type="text"
                bind:value={medium}
                placeholder="e.g., Oil, Watercolor, Acrylic"
                disabled={isSubmitting}
              />
            </div>
          </div>

          <div class="form-group">
            <label for="date-created">Date Created</label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <input
                id="date-created"
                type="date"
                bind:value={dateCreated}
                disabled={isSubmitting}
              />
            </div>
          </div>

          <div class="form-group">
            <label for="artwork-size">Size</label>
            <div class="input-wrapper">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="input-icon"><path d="M21 6H3"></path><path d="M10 12H3"></path><path d="M10 18H3"></path><circle cx="18" cy="12" r="3"></circle></svg>
              <input
                id="artwork-size"
                type="text"
                bind:value={artworkSize}
                placeholder="e.g., 24x36in, 3x3x3ft"
                disabled={isSubmitting}
              />
            </div>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn-primary" disabled={isSubmitting || !csrfToken}>
          {isSubmitting ? 'Creating...' : 'Create Artwork'}
        </button>
        <a href="/artworks" class="btn-secondary">Cancel</a>
      </div>
    </form>
  </div>
</div>

<style>
  .container {
    max-width: 1000px;
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
    margin: 0 0 2rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
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

  .form-group input[type="text"],
  .form-group input[type="date"] {
    width: 100%;
    padding: 0.75rem 1rem 0.75rem 2.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 1rem;
    transition: all 0.2s;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="date"]:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(90, 159, 212, 0.1);
  }

  .form-group input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .artwork-selector {
    position: relative;
  }

  .search-wrapper {
    position: relative;
  }

  .dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    max-height: 300px;
    overflow-y: auto;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    margin-top: 0.25rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    z-index: 10;
  }

  .dropdown-item {
    width: 100%;
    padding: 0.75rem 1rem;
    background: none;
    border: none;
    border-bottom: 1px solid var(--border-color);
    cursor: pointer;
    text-align: left;
    transition: background 0.2s;
  }

  .dropdown-item:hover {
    background: var(--bg-tertiary);
  }

  .dropdown-item:last-child {
    border-bottom: none;
  }

  .option-content {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .option-id code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-family: monospace;
    font-size: 0.8rem;
    font-weight: 600;
  }

  .option-name {
    color: var(--text-primary);
    font-weight: 500;
  }

  .form-group small {
    display: block;
    margin-top: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.8rem;
  }

  .form-group small.warning {
    color: #ff9800;
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

  .artist-display-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    background: var(--bg-secondary);
    border: 1px solid var(--accent-color);
    border-radius: 6px;
  }
  
  .artist-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .artist-name {
    font-weight: 600;
    color: var(--text-primary);
  }

  .artist-id-badge {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-family: monospace;
  }

  .artist-status {
    font-size: 0.8rem;
    color: var(--accent-color);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
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
