<script>
  import { onMount } from 'svelte';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { goto } from '$app/navigation';
  import { extractErrorMessage } from '$lib/utils/errorMessages';
  import ArtworkDeleteModal from '$lib/components/ArtworkDeleteModal.svelte';

  export let data;

  let csrfToken = '';
  let isSubmitting = false;
  let submitError = '';
  let showDeleteModal = false;

  // Form fields - pre-populate from artwork data
  let title = data.artwork.title || '';
  let artistId = data.artwork.artist?.id || '';
  let storageId = data.artwork.storage?.id || '';
  let medium = data.artwork.medium || '';
  let dateCreated = data.artwork.date_created ? data.artwork.date_created.split('T')[0] : '';
  let artworkSize = data.artwork.size || '';

  // Searchable dropdowns
  let artistSearch = data.artwork.artist ? `${data.artwork.artist.id} - ${data.artwork.artist.name}` : '';
  let showArtistDropdown = false;
  let storageSearch = data.artwork.storage ? `${data.artwork.storage.id} - ${data.artwork.storage.location}${data.artwork.storage.type ? ` (${data.artwork.storage.type})` : ''}` : '';
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

  const openDeleteModal = () => {
    showDeleteModal = true;
  };

  const closeDeleteModal = () => {
    showDeleteModal = false;
  };

  const handleDeleteSuccess = (result) => {
    // Redirect based on deletion type
    if (result.deletion_type === 'Soft-deleted') {
      // For soft delete, go back to artwork detail page
      goto(`/artworks/${data.artwork.id}`);
    } else {
      // For hard delete or force delete, redirect to artworks list
      goto('/artworks');
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

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks/${data.artwork.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorMessage = await extractErrorMessage(response, 'update artwork');
        throw new Error(errorMessage);
      }

      // Redirect to the artwork's detail page
      goto(`/artworks/${data.artwork.id}`);
    } catch (err) {
      submitError = err.message || 'An error occurred while updating the artwork. Suggestion: Check all fields and try again.';
      isSubmitting = false;
    }
  };
</script>

<div class="container">
  <div class="header">
    <a href="/artworks/{data.artwork.id}" class="back-link">← Back to Artwork</a>
  </div>

  <div class="form-container">
    <h1>Edit Artwork</h1>
    <p class="artwork-id">Artwork ID: <code>{data.artwork.id}</code></p>

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

      <div class="details-grid">
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
      </div>

      <div class="form-actions">
        <button type="submit" class="btn-primary" disabled={isSubmitting || !csrfToken}>
          {isSubmitting ? 'Updating...' : 'Update Artwork'}
        </button>
        <a href="/artworks/{data.artwork.id}" class="btn-secondary">Cancel</a>
        {#if !data.artwork.is_deleted}
          <button type="button" on:click={openDeleteModal} class="btn-danger">Delete Artwork</button>
        {/if}
      </div>
    </form>
  </div>
</div>

<!-- Delete Modal -->
{#if showDeleteModal}
  <ArtworkDeleteModal
    artworkId={data.artwork.id}
    artworkTitle={data.artwork.title}
    onSuccess={handleDeleteSuccess}
    onCancel={closeDeleteModal}
  />
{/if}

<style>
  .container {
    max-width: 700px;
    margin: 0 auto;
    padding: 2rem;
    animation: pageEnter 0.3s ease-out;
  }

  @keyframes pageEnter {
    from {
      opacity: 0;
      transform: translateY(12px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .header {
    margin-bottom: 1.5rem;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.9rem;
    padding: 8px 12px;
    margin-left: -12px;
    border-radius: 8px;
    transition: background 0.15s ease;
  }

  .back-link:hover {
    background: rgba(0, 122, 255, 0.08);
  }

  .form-container {
    background: var(--bg-primary);
    border-radius: 12px;
    padding: 2.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  h1 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
    font-weight: 500;
    letter-spacing: -0.5px;
  }

  .artwork-id {
    margin: 0 0 2rem 0;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .artwork-id code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-family: 'SF Mono', 'Consolas', monospace;
    font-weight: 600;
    font-size: 0.8rem;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
    font-weight: 500;
    font-size: 0.9rem;
  }

  .required {
    color: var(--error-color);
  }

  .form-group input[type="text"],
  .form-group input[type="date"] {
    width: 100%;
    height: 48px;
    padding: 0 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 1rem;
    box-sizing: border-box;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="date"]:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .form-group input::placeholder {
    color: var(--text-tertiary);
  }

  .form-group input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* Details Grid - 2 column layout */
  .details-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem 1.5rem;
    margin-bottom: 0.5rem;
  }

  .details-grid .form-group:last-child {
    grid-column: 1 / -1;
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
    max-height: 320px;
    overflow-y: auto;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    margin-top: 6px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12), 0 1px 3px rgba(0, 0, 0, 0.08);
    z-index: 10;
  }

  .dropdown-item {
    width: 100%;
    padding: 12px 16px;
    background: none;
    border: none;
    border-bottom: 1px solid var(--border-color);
    cursor: pointer;
    text-align: left;
    transition: background 0.15s ease;
  }

  .dropdown-item:hover {
    background: var(--bg-tertiary);
  }

  .dropdown-item:first-child {
    border-radius: 10px 10px 0 0;
  }

  .dropdown-item:last-child {
    border-bottom: none;
    border-radius: 0 0 10px 10px;
  }

  .dropdown-item:only-child {
    border-radius: 10px;
  }

  .option-content {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .option-id code {
    display: inline-block;
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 3px 8px;
    border-radius: 4px;
    font-family: 'SF Mono', 'Consolas', monospace;
    font-size: 0.8rem;
    font-weight: 600;
  }

  .option-name {
    color: var(--text-primary);
    font-weight: 500;
  }

  .form-group small {
    display: block;
    margin-top: 6px;
    color: var(--text-secondary);
    font-size: 0.8rem;
  }

  .form-group small.warning {
    color: #f59e0b;
    background: rgba(245, 158, 11, 0.1);
    padding: 6px 10px;
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .form-actions {
    display: flex;
    gap: 12px;
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border-color);
  }

  .btn-primary {
    padding: 0 28px;
    height: 44px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 22px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 500;
    transition: all 0.15s ease;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.1);
  }

  .btn-primary:hover:not(:disabled) {
    filter: brightness(1.05);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
    transform: translateY(-1px);
  }

  .btn-primary:active:not(:disabled) {
    transform: translateY(0);
  }

  .btn-primary:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
    box-shadow: none;
    transform: none;
    filter: none;
  }

  .btn-secondary {
    padding: 0 20px;
    height: 44px;
    background: transparent;
    color: var(--accent-color);
    border: none;
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 500;
    font-size: 0.95rem;
    transition: background 0.15s ease;
  }

  .btn-secondary:hover {
    background: rgba(0, 122, 255, 0.08);
  }

  .btn-danger {
    padding: 0 24px;
    height: 44px;
    background: transparent;
    color: var(--error-color);
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 500;
    transition: background 0.15s ease;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-left: auto;
  }

  .btn-danger:hover:not(:disabled) {
    background: rgba(211, 47, 47, 0.1);
  }

  .btn-danger:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .error-message {
    padding: 12px 16px;
    margin-bottom: 1.5rem;
    background: rgba(234, 67, 53, 0.08);
    color: #ea4335;
    border-radius: 8px;
    font-size: 0.9rem;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  @media (max-width: 768px) {
    .container {
      padding: 1rem;
    }

    .form-container {
      padding: 1.5rem;
      border-radius: 0;
      box-shadow: none;
    }

    .details-grid {
      grid-template-columns: 1fr;
    }

    .details-grid .form-group:last-child {
      grid-column: 1;
    }

    .form-actions {
      flex-direction: column;
    }

    .btn-primary,
    .btn-secondary,
    .btn-danger {
      width: 100%;
      margin-left: 0;
    }

    .btn-danger {
      order: 3;
      background: rgba(211, 47, 47, 0.1);
    }
  }
</style>

