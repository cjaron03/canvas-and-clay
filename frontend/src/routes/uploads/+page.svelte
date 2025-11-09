<script>
  import { onMount } from 'svelte';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { extractErrorMessage } from '$lib/utils/errorMessages';

  let activeTab = 'existing'; // 'existing' or 'new'
  let csrfToken = '';

  // Existing artwork upload state
  let artworkId = '';
  let selectedFiles = [];
  let isPrimary = false;
  let uploadStatus = '';
  let uploadError = '';
  let uploadProgress = [];

  // Artwork selector state
  let artworks = [];
  let artworkSearch = '';
  let showDropdown = false;
  let isLoadingArtworks = false;

  // Orphaned photo upload state
  let orphanedFiles = [];
  let orphanedStatus = '';
  let orphanedError = '';
  let orphanedProgress = [];
  let uploadedPhotoIds = [];

  // Fetch CSRF token on mount
  onMount(async () => {
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        csrfToken = data.csrf_token;
      }
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
    }

    // Load artworks for dropdown
    await loadArtworks();
  });

  // Load artworks from API
  const loadArtworks = async () => {
    isLoadingArtworks = true;
    try {
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/artworks?per_page=100`,
        {
          credentials: 'include'
        }
      );

      if (response.ok) {
        const data = await response.json();
        artworks = data.artworks || [];
      }
    } catch (error) {
      console.error('Failed to load artworks:', error);
    }
    isLoadingArtworks = false;
  };

  // Filter artworks based on search
  $: filteredArtworks = artworkSearch.trim()
    ? artworks.filter(artwork => {
        const searchLower = artworkSearch.toLowerCase();
        return (
          artwork.id.toLowerCase().includes(searchLower) ||
          artwork.title.toLowerCase().includes(searchLower) ||
          artwork.artist?.name.toLowerCase().includes(searchLower)
        );
      })
    : artworks;

  // Select artwork from dropdown
  const selectArtwork = (artwork) => {
    artworkId = artwork.id;
    artworkSearch = `${artwork.id} - ${artwork.title}`;
    showDropdown = false;
  };

  // Handle search input
  const handleArtworkSearch = (event) => {
    artworkSearch = event.target.value;
    showDropdown = artworkSearch.length > 0;
  };

  // Handle search focus
  const handleSearchFocus = () => {
    if (artworkSearch.length > 0) {
      showDropdown = true;
    }
  };

  // Handle file selection for existing artwork
  const handleFileSelect = (event) => {
    selectedFiles = Array.from(event.target.files);
    uploadStatus = '';
    uploadError = '';
    uploadProgress = selectedFiles.map(() => ({ status: 'pending', message: '' }));
  };

  // Remove a file from the existing artwork upload queue
  const removeFile = (index) => {
    selectedFiles = selectedFiles.filter((_, i) => i !== index);
    uploadProgress = uploadProgress.filter((_, i) => i !== index);
    uploadStatus = '';
    uploadError = '';
  };

  // Handle file selection for orphaned photos
  const handleOrphanedFileSelect = (event) => {
    orphanedFiles = Array.from(event.target.files);
    orphanedStatus = '';
    orphanedError = '';
    orphanedProgress = orphanedFiles.map(() => ({ status: 'pending', message: '' }));
    uploadedPhotoIds = [];
  };

  // Remove a file from the orphaned photos upload queue
  const removeOrphanedFile = (index) => {
    orphanedFiles = orphanedFiles.filter((_, i) => i !== index);
    orphanedProgress = orphanedProgress.filter((_, i) => i !== index);
    orphanedStatus = '';
    orphanedError = '';
  };

  // Upload photos to existing artwork
  const uploadToExistingArtwork = async () => {
    if (!artworkId.trim()) {
      uploadError = 'Please select an artwork from the dropdown';
      return;
    }

    if (selectedFiles.length === 0) {
      uploadError = 'Please select at least one photo';
      return;
    }

    uploadStatus = 'Uploading...';
    uploadError = '';

    for (let i = 0; i < selectedFiles.length; i++) {
      const file = selectedFiles[i];
      uploadProgress[i] = { status: 'uploading', message: 'Uploading...' };
      uploadProgress = [...uploadProgress]; // Trigger reactivity

      const formData = new FormData();
      formData.append('photo', file);

      // Set first photo as primary if checkbox is checked
      if (isPrimary && i === 0) {
        formData.append('is_primary', 'true');
      }

      try {
        const response = await fetch(
          `${PUBLIC_API_BASE_URL}/api/artworks/${artworkId.trim()}/photos`,
          {
            method: 'POST',
            headers: {
              'X-CSRFToken': csrfToken
            },
            credentials: 'include',
            body: formData
          }
        );

        if (response.ok) {
          uploadProgress[i] = { status: 'success', message: 'Uploaded successfully!' };
        } else {
          const errorMessage = await extractErrorMessage(response, 'upload photo');
          uploadProgress[i] = {
            status: 'error',
            message: errorMessage
          };
        }
      } catch (error) {
        uploadProgress[i] = {
          status: 'error',
          message: `Upload failed: ${error.message}. Suggestion: Check your internet connection and try again.`
        };
      }

      uploadProgress = [...uploadProgress]; // Trigger reactivity
    }

    const allSuccess = uploadProgress.every(p => p.status === 'success');
    if (allSuccess) {
      uploadStatus = `Successfully uploaded ${selectedFiles.length} photo(s)!`;
      // Reset form
      selectedFiles = [];
      artworkId = '';
      isPrimary = false;
      if (document.getElementById('file-input-existing')) {
        document.getElementById('file-input-existing').value = '';
      }
    } else {
      uploadStatus = 'Some uploads failed. Check the error message shown with each file above.';
    }
  };

  // Upload orphaned photos
  const uploadOrphanedPhotos = async () => {
    if (orphanedFiles.length === 0) {
      orphanedError = 'Please select at least one photo';
      return;
    }

    orphanedStatus = 'Uploading...';
    orphanedError = '';
    uploadedPhotoIds = [];

    for (let i = 0; i < orphanedFiles.length; i++) {
      const file = orphanedFiles[i];
      orphanedProgress[i] = { status: 'uploading', message: 'Uploading...' };
      orphanedProgress = [...orphanedProgress];

      const formData = new FormData();
      formData.append('photo', file);

      try {
        const response = await fetch(
          `${PUBLIC_API_BASE_URL}/api/photos`,
          {
            method: 'POST',
            headers: {
              'X-CSRFToken': csrfToken
            },
            credentials: 'include',
            body: formData
          }
        );

        if (response.ok) {
          const data = await response.json();
          uploadedPhotoIds.push(data.photo.id);
          orphanedProgress[i] = {
            status: 'success',
            message: `Uploaded! Photo ID: ${data.photo.id}`
          };
        } else {
          const errorMessage = await extractErrorMessage(response, 'upload photo');
          orphanedProgress[i] = {
            status: 'error',
            message: errorMessage
          };
        }
      } catch (error) {
        orphanedProgress[i] = {
          status: 'error',
          message: `Upload failed: ${error.message}. Suggestion: Check your internet connection and try again.`
        };
      }

      orphanedProgress = [...orphanedProgress];
    }

    const allSuccess = orphanedProgress.every(p => p.status === 'success');
    if (allSuccess) {
      orphanedStatus = `Successfully uploaded ${orphanedFiles.length} photo(s)!`;
      // Reset form
      orphanedFiles = [];
      if (document.getElementById('file-input-orphaned')) {
        document.getElementById('file-input-orphaned').value = '';
      }
    } else {
      orphanedStatus = 'Some uploads failed. Check the error message shown with each file above.';
    }
  };
</script>

<h1>Upload Photos</h1>

<div class="tabs">
  <button
    class:active={activeTab === 'existing'}
    on:click={() => activeTab = 'existing'}
  >
    Upload to Existing Artwork
  </button>
  <button
    class:active={activeTab === 'new'}
    on:click={() => activeTab = 'new'}
  >
    Upload New Photos
  </button>
</div>

{#if activeTab === 'existing'}
  <div class="tab-content">
    <h2>Upload Photos to Existing Artwork</h2>
    <p>Search for an artwork below and select it to upload photos.</p>

    <form on:submit|preventDefault={uploadToExistingArtwork}>
      <div class="form-group artwork-selector">
        <label for="artwork-search">Search for Artwork</label>
        <div class="search-wrapper">
          <input
            id="artwork-search"
            type="text"
            bind:value={artworkSearch}
            on:input={handleArtworkSearch}
            on:focus={handleSearchFocus}
            placeholder="Search by ID, title, or artist name..."
            autocomplete="off"
          />
          {#if showDropdown && filteredArtworks.length > 0}
            <div class="dropdown">
              {#each filteredArtworks.slice(0, 10) as artwork}
                <button
                  type="button"
                  class="dropdown-item"
                  on:click={() => selectArtwork(artwork)}
                >
                  <div class="artwork-option">
                    <div class="artwork-id-option">
                      <code>{artwork.id}</code>
                    </div>
                    <div class="artwork-title">{artwork.title}</div>
                    <div class="artwork-artist">{artwork.artist?.name || 'Unknown Artist'}</div>
                  </div>
                </button>
              {/each}
            </div>
          {/if}
        </div>
        {#if isLoadingArtworks}
          <small>Loading artworks...</small>
        {:else if artworks.length === 0}
          <small>No artworks found. <a href="/artworks">Browse artworks</a> to create one first.</small>
        {:else}
          <small>{artworks.length} artworks available. Select one from the dropdown above.</small>
        {/if}
        {#if !artworkId && artworkSearch && selectedFiles.length > 0}
          <small class="warning">⚠ Please select an artwork from the dropdown before uploading</small>
        {/if}
      </div>

      <div class="form-group">
        <label for="file-input-existing">Select Photos</label>
        <input
          id="file-input-existing"
          type="file"
          accept="image/jpeg,image/png,image/webp,image/avif"
          multiple
          on:change={handleFileSelect}
          required
        />
        <small>Accepted formats: JPG, PNG, WebP, AVIF. Max 10MB per file.</small>
      </div>

      {#if selectedFiles.length > 0}
        <div class="form-group">
          <label>
            <input type="checkbox" bind:checked={isPrimary} />
            Set first photo as primary
          </label>
        </div>

        <div class="file-preview">
          <strong>Selected files ({selectedFiles.length}):</strong>
          <ul>
            {#each selectedFiles as file, index}
              <li>
                <div class="file-item">
                  <div class="file-info">{file.name} ({(file.size / 1024).toFixed(1)} KB)</div>
                  {#if !uploadProgress[index] || uploadProgress[index].status === 'pending'}
                    <button
                      type="button"
                      class="remove-btn"
                      on:click={() => removeFile(index)}
                      title="Remove this file"
                    >
                      ✕
                    </button>
                  {/if}
                </div>
                {#if uploadProgress[index]}
                  <div class="status-{uploadProgress[index].status}">
                    {uploadProgress[index].message}
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/if}

      <button type="submit" disabled={!csrfToken || selectedFiles.length === 0}>
        Upload Photos
      </button>
    </form>

    {#if uploadStatus}
      <div class="status-message success">{uploadStatus}</div>
    {/if}
    {#if uploadError}
      <div class="status-message error">{uploadError}</div>
    {/if}
  </div>

{:else if activeTab === 'new'}
  <div class="tab-content">
    <h2>Upload New Photos</h2>
    <p>Upload photos that will be available to associate with artworks later.</p>

    <form on:submit|preventDefault={uploadOrphanedPhotos}>
      <div class="form-group">
        <label for="file-input-orphaned">Select Photos</label>
        <input
          id="file-input-orphaned"
          type="file"
          accept="image/jpeg,image/png,image/webp,image/avif"
          multiple
          on:change={handleOrphanedFileSelect}
          required
        />
        <small>Accepted formats: JPG, PNG, WebP, AVIF. Max 10MB per file.</small>
      </div>

      {#if orphanedFiles.length > 0}
        <div class="file-preview">
          <strong>Selected files ({orphanedFiles.length}):</strong>
          <ul>
            {#each orphanedFiles as file, index}
              <li>
                <div class="file-item">
                  <div class="file-info">{file.name} ({(file.size / 1024).toFixed(1)} KB)</div>
                  {#if !orphanedProgress[index] || orphanedProgress[index].status === 'pending'}
                    <button
                      type="button"
                      class="remove-btn"
                      on:click={() => removeOrphanedFile(index)}
                      title="Remove this file"
                    >
                      ✕
                    </button>
                  {/if}
                </div>
                {#if orphanedProgress[index]}
                  <div class="status-{orphanedProgress[index].status}">
                    {orphanedProgress[index].message}
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/if}

      <button type="submit" disabled={!csrfToken || orphanedFiles.length === 0}>
        Upload Photos
      </button>
    </form>

    {#if uploadedPhotoIds.length > 0}
      <div class="photo-ids">
        <strong>Uploaded Photo IDs:</strong>
        <ul>
          {#each uploadedPhotoIds as photoId}
            <li><code>{photoId}</code></li>
          {/each}
        </ul>
        <p>Save these IDs to associate photos with artworks later.</p>
      </div>
    {/if}

    {#if orphanedStatus}
      <div class="status-message success">{orphanedStatus}</div>
    {/if}
    {#if orphanedError}
      <div class="status-message error">{orphanedError}</div>
    {/if}
  </div>
{/if}

<style>
  .tabs {
    display: flex;
    gap: 1rem;
    margin-bottom: 2rem;
    border-bottom: 2px solid var(--border-color);
  }

  .tabs button {
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    border-bottom: 3px solid transparent;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s;
    color: var(--text-primary);
  }

  .tabs button:hover {
    background: var(--bg-tertiary);
  }

  .tabs button.active {
    border-bottom-color: var(--accent-color);
    font-weight: bold;
  }

  .tab-content {
    padding: 1rem 0;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: bold;
    color: var(--text-primary);
  }

  .form-group input[type="text"],
  .form-group input[type="file"] {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-secondary);
    color: var(--text-primary);
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="file"]:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .form-group small {
    display: block;
    margin-top: 0.25rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  button[type="submit"] {
    padding: 0.75rem 1.5rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
  }

  button[type="submit"]:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  button[type="submit"]:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
  }

  .file-preview {
    padding: 1rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .file-preview ul {
    margin: 0.5rem 0 0 0;
    padding-left: 1.5rem;
    list-style: none;
  }

  .file-preview li {
    margin: 0.75rem 0;
    padding: 0.5rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
    border-left: 3px solid var(--border-color);
  }

  .file-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }

  .file-info {
    color: var(--text-primary);
    margin-bottom: 0.25rem;
    flex: 1;
  }

  .remove-btn {
    background: rgba(211, 47, 47, 0.2);
    color: var(--error-color);
    border: none;
    border-radius: 4px;
    width: 28px;
    height: 28px;
    font-size: 1.25rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    transition: all 0.2s;
    flex-shrink: 0;
  }

  .remove-btn:hover {
    background: rgba(211, 47, 47, 0.3);
    transform: scale(1.1);
  }

  .remove-btn:active {
    transform: scale(0.95);
  }

  .status-message {
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
  }

  .status-message.success {
    background: rgba(76, 175, 80, 0.1);
    color: var(--success-color);
    border: 1px solid var(--success-color);
  }

  .status-message.error {
    background: rgba(211, 47, 47, 0.2);
    color: var(--error-color);
    border: 1px solid var(--error-color);
  }

  .status-pending {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-top: 0.25rem;
  }

  .status-uploading {
    color: var(--accent-color);
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
  }

  .status-success {
    color: var(--success-color);
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: rgba(76, 175, 80, 0.1);
    border-radius: 3px;
    border-left: 3px solid var(--success-color);
  }

  .status-error {
    color: var(--error-color);
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: rgba(211, 47, 47, 0.2);
    border-radius: 3px;
    border-left: 3px solid var(--error-color);
  }

  .photo-ids {
    padding: 1rem;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    margin: 1rem 0;
  }

  .photo-ids code {
    background: var(--bg-secondary);
    color: var(--text-primary);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
  }

  /* Artwork selector dropdown styles */
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

  .artwork-option {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .artwork-id-option code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-size: 0.875rem;
    font-weight: bold;
  }

  .artwork-title {
    color: var(--text-primary);
    font-weight: 500;
  }

  .artwork-artist {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .form-group small.warning {
    color: #ff9800;
  }
</style>
