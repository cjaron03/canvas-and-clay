<script>
  import { onMount } from 'svelte';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { extractErrorMessage } from '$lib/utils/errorMessages';

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
    <a href="/artworks" class="back-link">← Back to Artworks</a>
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
      <div class="form-group">
        <label for="title">Title <span class="required">*</span></label>
        <input
          id="title"
          type="text"
          bind:value={title}
          placeholder="Enter artwork title"
          required
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group artwork-selector">
        <label for="artist-search">Artist <span class="required">*</span></label>
        <div class="search-wrapper">
          <input
            id="artist-search"
            type="text"
            bind:value={artistSearch}
            on:input={handleArtistSearch}
            on:focus={() => { if (artistSearch.length > 0) showArtistDropdown = true; }}
            placeholder="Search by ID or name..."
            autocomplete="off"
            required
            disabled={isSubmitting}
          />
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
        </div>
        <input
          type="hidden"
          bind:value={artistId}
          required
        />
        {#if artistId && !data.artists.find(a => a.id === artistId)}
          <small class="warning">⚠ This artist ID was not found in the list above</small>
        {/if}
      </div>

      <div class="form-group artwork-selector">
        <label for="storage-search">Storage Location <span class="required">*</span></label>
        <div class="search-wrapper">
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
        <input
          type="hidden"
          bind:value={storageId}
          required
        />
        {#if storageId && !data.storage.find(s => s.id === storageId)}
          <small class="warning">⚠ This storage ID was not found in the list above</small>
        {/if}
      </div>

      <div class="form-group">
        <label for="medium">Medium</label>
        <input
          id="medium"
          type="text"
          bind:value={medium}
          placeholder="e.g., Oil, Watercolor, Acrylic"
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="date-created">Date Created</label>
        <input
          id="date-created"
          type="date"
          bind:value={dateCreated}
          disabled={isSubmitting}
        />
      </div>

      <div class="form-group">
        <label for="artwork-size">Size</label>
        <input
          id="artwork-size"
          type="text"
          bind:value={artworkSize}
          placeholder="e.g., 24x36in, 3x3x3ft"
          disabled={isSubmitting}
        />
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
    margin: 0 0 2rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
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

  .form-group input[type="text"],
  .form-group input[type="date"] {
    width: 100%;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 1rem;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="date"]:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .form-group input:disabled {
    opacity: 0.5;
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
    max-height: 400px;
    overflow-y: auto;
    background: var(--bg-secondary);
    border: 1px solid var(--accent-color);
    border-radius: 4px;
    margin-top: 0.25rem;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
    z-index: 10;
  }

  .dropdown-item {
    width: 100%;
    padding: 0.75rem;
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
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-size: 0.875rem;
    font-weight: bold;
  }

  .option-name {
    color: var(--text-primary);
    font-weight: 500;
  }

  .form-group small {
    display: block;
    margin-top: 0.25rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .form-group small.warning {
    color: #ff9800;
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

