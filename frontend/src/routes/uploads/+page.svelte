<script>
  import { onMount } from 'svelte';
  import { auth } from '$lib/stores/auth';
  import { get } from 'svelte/store';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { extractErrorMessage } from '$lib/utils/errorMessages';
  import { validateImageFile } from '$lib/utils/fileValidation';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';

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

  // Auth check
  $: isAdmin = $auth.user?.role === 'admin';
  let loadError = '';

  // Fetch CSRF token on mount
  onMount(async () => {
    try {
      await auth.init();

      // Check if user is authenticated
      if (!$auth.isAuthenticated) {
        if ($page.url.pathname.startsWith('/uploads')) {
          loadError = 'Authentication required. Please log in.';
          goto('/login');
        }
        return;
      }

      // Check if user is artist or admin (both roles can upload)
      if ($auth.user?.role !== 'artist' && $auth.user?.role !== 'admin') {
        if ($page.url.pathname.startsWith('/uploads')) {
          loadError = 'You need to be an artist to access this page.';
          goto('/');
        }
        return;
      }

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
      const authedState = get(auth);
      const ownedParam =
        authedState?.isAuthenticated && authedState?.user?.role === 'artist' ? '&owned=true' : '';
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/artworks?per_page=100${ownedParam}`,
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
    const files = event.target.files || event.dataTransfer?.files;
    if (files) {
      const fileArray = Array.from(files);
      const errors = [];
      const validFiles = [];
      
      fileArray.forEach(file => {
        const validation = validateImageFile(file);
        if (validation.valid) {
          validFiles.push(file);
        } else {
          errors.push(validation.error);
        }
      });
      
      selectedFiles = validFiles;
      uploadStatus = '';
      
      if (errors.length > 0) {
        uploadError = errors.join(' ');
      } else {
        uploadError = '';
      }
      
      uploadProgress = validFiles.map(() => ({ status: 'pending', message: '' }));
    }
  };

  // Drag and drop handlers for existing artwork
  let isDraggingExisting = false;
  let fileInputWrapperExisting;

  const handleDragEnterExisting = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      isDraggingExisting = true;
    }
  };

  const handleDragOverExisting = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      e.dataTransfer.dropEffect = 'copy';
      if (!isDraggingExisting) {
        isDraggingExisting = true;
      }
    }
  };

  const handleDragLeaveExisting = (e) => {
    e.preventDefault();
    e.stopPropagation();
    // Use a timeout to check if we're still dragging over
    setTimeout(() => {
      if (fileInputWrapperExisting) {
        const rect = fileInputWrapperExisting.getBoundingClientRect();
        const x = e.clientX;
        const y = e.clientY;
        if (x < rect.left || x > rect.right || y < rect.top || y > rect.bottom) {
          isDraggingExisting = false;
        }
      }
    }, 50);
  };

  const handleDropExisting = (e) => {
    e.preventDefault();
    e.stopPropagation();
    isDraggingExisting = false;
    
    const files = e.dataTransfer.files;
    
    if (files && files.length > 0) {
      const fileArray = Array.from(files);
      const errors = [];
      const validFiles = [];
      
      fileArray.forEach(file => {
        const validation = validateImageFile(file);
        if (validation.valid) {
          validFiles.push(file);
        } else {
          errors.push(validation.error);
        }
      });
      
      // Update state with valid files
      selectedFiles = validFiles;
      uploadStatus = '';
      
      if (errors.length > 0) {
        uploadError = errors.join(' ');
      } else {
        uploadError = '';
      }
      
      uploadProgress = validFiles.map(() => ({ status: 'pending', message: '' }));
      
      // Also update the file input for form submission
      try {
        const fileInput = document.getElementById('file-input-existing');
        if (fileInput && validFiles.length > 0) {
          const dataTransfer = new DataTransfer();
          validFiles.forEach(file => {
            dataTransfer.items.add(file);
          });
          fileInput.files = dataTransfer.files;
        }
      } catch (err) {
        console.error('Error setting file input:', err);
      }
    }
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
    const files = event.target.files || event.dataTransfer?.files;
    if (files) {
      const fileArray = Array.from(files);
      const errors = [];
      const validFiles = [];
      
      fileArray.forEach(file => {
        const validation = validateImageFile(file);
        if (validation.valid) {
          validFiles.push(file);
        } else {
          errors.push(validation.error);
        }
      });
      
      orphanedFiles = validFiles;
      orphanedStatus = '';
      
      if (errors.length > 0) {
        orphanedError = errors.join(' ');
      } else {
        orphanedError = '';
      }
      
      orphanedProgress = validFiles.map(() => ({ status: 'pending', message: '' }));
      uploadedPhotoIds = [];
    }
  };

  // Drag and drop handlers for orphaned photos
  let isDraggingOrphaned = false;
  let fileInputWrapperOrphaned;

  const handleDragEnterOrphaned = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      isDraggingOrphaned = true;
    }
  };

  const handleDragOverOrphaned = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')) {
      e.dataTransfer.dropEffect = 'copy';
      if (!isDraggingOrphaned) {
        isDraggingOrphaned = true;
      }
    }
  };

  const handleDragLeaveOrphaned = (e) => {
    e.preventDefault();
    e.stopPropagation();
    // Use a timeout to check if we're still dragging over
    setTimeout(() => {
      if (fileInputWrapperOrphaned) {
        const rect = fileInputWrapperOrphaned.getBoundingClientRect();
        const x = e.clientX;
        const y = e.clientY;
        if (x < rect.left || x > rect.right || y < rect.top || y > rect.bottom) {
          isDraggingOrphaned = false;
        }
      }
    }, 50);
  };

  const handleDropOrphaned = (e) => {
    e.preventDefault();
    e.stopPropagation();
    isDraggingOrphaned = false;
    
    const files = e.dataTransfer.files;
    
    if (files && files.length > 0) {
      const fileArray = Array.from(files);
      const errors = [];
      const validFiles = [];
      
      fileArray.forEach(file => {
        const validation = validateImageFile(file);
        if (validation.valid) {
          validFiles.push(file);
        } else {
          errors.push(validation.error);
        }
      });
      
      // Update state with valid files
      orphanedFiles = validFiles;
      orphanedStatus = '';
      
      if (errors.length > 0) {
        orphanedError = errors.join(' ');
      } else {
        orphanedError = '';
      }
      
      orphanedProgress = validFiles.map(() => ({ status: 'pending', message: '' }));
      uploadedPhotoIds = [];
      
      // Also update the file input for form submission
      try {
        const fileInput = document.getElementById('file-input-orphaned');
        if (fileInput && validFiles.length > 0) {
          const dataTransfer = new DataTransfer();
          validFiles.forEach(file => {
            dataTransfer.items.add(file);
          });
          fileInput.files = dataTransfer.files;
        }
      } catch (err) {
        console.error('Error setting file input:', err);
      }
    }
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

{#if loadError}
  <div class="status-message error">{loadError}</div>
{/if}

{#if isAdmin}
  <div class="tabs">
    <button
      class:active={activeTab === 'existing'}
      class:tab-existing={activeTab === 'existing'}
      on:click={() => activeTab = 'existing'}
    >
      <span class="tab-icon">Link</span>
      <span class="tab-label">Upload to Existing Artwork</span>
      <span class="tab-description">Add photos to artworks already in the database</span>
    </button>
    <button
      class:active={activeTab === 'new'}
      class:tab-new={activeTab === 'new'}
      on:click={() => activeTab = 'new'}
    >
      <span class="tab-icon">Upload</span>
      <span class="tab-label">Upload New Photos</span>
      <span class="tab-description">Upload photos to associate with artworks later</span>
    </button>
  </div>
{:else}
  <!-- Artist view header logic simplified -->
{/if}

{#if activeTab === 'existing'}
  <div class="tab-content tab-content-existing">
    <div class="tab-header">
      <h2>Upload Photos to Existing Artwork</h2>
      <p class="tab-subtitle">Search for an artwork below and select it to upload photos.</p>
    </div>

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
        <div 
          class="file-input-wrapper"
          class:dragging={isDraggingExisting}
          bind:this={fileInputWrapperExisting}
          role="button"
          tabindex="0"
          aria-label="File drop zone. Drag and drop files here or click Browse to select files."
          on:dragenter={handleDragEnterExisting}
          on:dragover={handleDragOverExisting}
          on:dragleave={handleDragLeaveExisting}
          on:drop={handleDropExisting}
        >
          <input
            id="file-input-existing"
            type="file"
            accept="image/jpeg,image/png,image/webp,image/avif"
            multiple
            on:change={handleFileSelect}
            required
            class="file-input-hidden"
          />
          <label 
            for="file-input-existing" 
            class="file-input-label"
          >
            {#if selectedFiles.length > 0}
              <span class="file-input-text">
                {selectedFiles.length} file{selectedFiles.length !== 1 ? 's' : ''} selected
              </span>
            {:else}
              <span class="file-input-text">Choose files or drag and drop</span>
            {/if}
            <span class="file-input-button">Browse</span>
          </label>
          {#if isDraggingExisting}
            <div class="drag-overlay">
              <div class="drag-indicator">
                <div class="drag-icon">Drop</div>
                <div class="drag-text">Drop files here</div>
              </div>
            </div>
          {/if}
        </div>
        <small>Accepted formats: JPG, PNG, WebP, AVIF. Max 10MB per file.</small>
      </div>

      {#if selectedFiles.length > 0}
        <div class="form-group checkbox-group">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={isPrimary} class="checkbox-input" />
            <span>Set first photo as primary</span>
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

{:else if activeTab === 'new' && isAdmin}
  <div class="tab-content tab-content-new">
    <div class="tab-header">
      <h2>Upload New Photos</h2>
      <p class="tab-subtitle">Upload photos that will be available to associate with artworks later.</p>
    </div>

    <form on:submit|preventDefault={uploadOrphanedPhotos}>
      <div class="form-group">
        <label for="file-input-orphaned">Select Photos</label>
        <div 
          class="file-input-wrapper"
          class:dragging={isDraggingOrphaned}
          bind:this={fileInputWrapperOrphaned}
          role="button"
          tabindex="0"
          aria-label="File drop zone. Drag and drop files here or click Browse to select files."
          on:dragenter={handleDragEnterOrphaned}
          on:dragover={handleDragOverOrphaned}
          on:dragleave={handleDragLeaveOrphaned}
          on:drop={handleDropOrphaned}
        >
          <input
            id="file-input-orphaned"
            type="file"
            accept="image/jpeg,image/png,image/webp,image/avif"
            multiple
            on:change={handleOrphanedFileSelect}
            required
            class="file-input-hidden"
          />
          <label 
            for="file-input-orphaned" 
            class="file-input-label"
          >
            {#if orphanedFiles.length > 0}
              <span class="file-input-text">
                {orphanedFiles.length} file{orphanedFiles.length !== 1 ? 's' : ''} selected
              </span>
            {:else}
              <span class="file-input-text">Choose files or drag and drop</span>
            {/if}
            <span class="file-input-button">Browse</span>
          </label>
          {#if isDraggingOrphaned}
            <div class="drag-overlay">
              <div class="drag-indicator">
                <div class="drag-icon">Drop</div>
                <div class="drag-text">Drop files here</div>
              </div>
            </div>
          {/if}
        </div>
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
  :global(.uploads-page) {
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

  .tabs {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .tabs button {
    padding: 1.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.15s ease;
    color: var(--text-primary);
    text-align: left;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    position: relative;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }

  .tabs button:hover {
    border-color: var(--accent-color);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .tabs button.active {
    border-color: var(--accent-color);
    background: var(--bg-primary);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .tabs button.tab-existing.active {
    border-left: 4px solid var(--accent-color);
  }

  .tabs button.tab-new.active {
    border-left: 4px solid #34a853;
  }

  .tab-icon {
    font-size: 0.875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
  }

  .tabs button.active .tab-icon {
    color: var(--accent-color);
  }

  .tabs button.tab-new.active .tab-icon {
    color: #4caf50;
  }

  .tab-label {
    font-weight: 600;
    font-size: 1.125rem;
    color: var(--text-primary);
  }

  .tab-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .tabs button.active .tab-label {
    color: var(--accent-color);
  }

  .tabs button.tab-new.active .tab-label {
    color: #4caf50;
  }

  .tab-content {
    padding: 2.5rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    margin-top: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .tab-content-existing {
    border-left: 4px solid var(--accent-color);
  }

  .tab-content-new {
    border-left: 4px solid #4caf50;
  }

  .tab-header {
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-color);
  }

  .tab-header h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--text-primary);
  }

  .tab-subtitle {
    margin: 0;
    color: var(--text-secondary);
    font-size: 1rem;
  }

  form {
    max-width: 600px;
    margin: 0 auto;
  }

  .form-group {
    margin-bottom: 2rem;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
    font-size: 0.875rem;
    color: var(--text-primary);
    letter-spacing: 0.1px;
  }

  .form-group input[type="text"] {
    width: 100%;
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 1rem;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .form-group input[type="text"]:hover {
    border-color: var(--text-tertiary);
  }

  .form-group input[type="text"]:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .file-input-wrapper {
    position: relative;
    width: 100%;
  }

  .file-input-label {
    pointer-events: none;
  }

  .file-input-label .file-input-button {
    pointer-events: auto;
  }

  .file-input-wrapper.dragging .file-input-label {
    border-color: var(--accent-color);
    border-style: solid;
    background: var(--bg-secondary);
    box-shadow: 0 0 0 3px rgba(90, 159, 212, 0.15);
  }

  .drag-overlay {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(90, 159, 212, 0.1);
    border: 3px dashed var(--accent-color);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
    pointer-events: none;
    animation: pulse 1.5s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
      transform: scale(1);
    }
    50% {
      opacity: 0.9;
      transform: scale(1.02);
    }
  }

  .drag-indicator {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    padding: 2rem;
    background: var(--bg-primary);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }

  .drag-icon {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent-color);
    text-transform: uppercase;
    letter-spacing: 2px;
    padding: 1rem 2rem;
    background: rgba(90, 159, 212, 0.1);
    border: 2px solid var(--accent-color);
    border-radius: 8px;
    animation: bounce 1s ease-in-out infinite;
  }

  @keyframes bounce {
    0%, 100% {
      transform: translateY(0);
    }
    50% {
      transform: translateY(-5px);
    }
  }

  .drag-text {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--accent-color);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .file-input-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }

  .file-input-label {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 1rem 1.25rem;
    border: 2px dashed var(--border-color);
    border-radius: 10px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.9375rem;
    cursor: pointer;
    transition: all 0.15s ease;
    gap: 1rem;
  }

  .file-input-label:hover {
    border-color: var(--accent-color);
    background: rgba(0, 122, 255, 0.04);
    border-style: solid;
  }

  .file-input-label:focus-within {
    outline: none;
    border-color: var(--accent-color);
    border-style: solid;
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }


  .file-input-text {
    flex: 1;
    text-align: left;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .file-input-label:hover .file-input-text {
    color: var(--accent-color);
  }

  .file-input-button {
    padding: 0 18px;
    height: 36px;
    display: flex;
    align-items: center;
    background: var(--accent-color);
    color: white;
    border-radius: 18px;
    font-size: 0.875rem;
    font-weight: 500;
    flex-shrink: 0;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .file-input-label:hover .file-input-button {
    filter: brightness(1.05);
    box-shadow: 0 2px 6px rgba(0, 122, 255, 0.3);
    transform: translateY(-1px);
  }

  .form-group small {
    display: block;
    margin-top: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.8125rem;
    line-height: 1.5;
  }

  button[type="submit"] {
    padding: 0 28px;
    height: 44px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 22px;
    cursor: pointer;
    font-size: 0.9375rem;
    font-weight: 500;
    letter-spacing: 0.25px;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    min-width: 140px;
  }

  button[type="submit"]:hover:not(:disabled) {
    filter: brightness(1.05);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
    transform: translateY(-1px);
  }

  button[type="submit"]:active:not(:disabled) {
    transform: translateY(0);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  button[type="submit"]:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
    box-shadow: none;
    transform: none;
  }

  .file-preview {
    padding: 1.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .file-preview strong {
    display: block;
    margin-bottom: 1rem;
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .file-preview ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .file-preview li {
    margin: 0.75rem 0;
    padding: 1rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    transition: all 0.15s ease;
  }

  .file-preview li:hover {
    border-color: var(--accent-color);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
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
    padding: 1rem 1.25rem;
    margin: 1.5rem 0;
    border-radius: 10px;
    font-weight: 500;
    font-size: 0.9375rem;
  }

  .status-message.success {
    background: rgba(76, 175, 80, 0.08);
    color: var(--success-color);
    border: 1px solid rgba(76, 175, 80, 0.3);
    box-shadow: 0 1px 3px rgba(76, 175, 80, 0.1);
  }

  .status-message.error {
    background: rgba(211, 47, 47, 0.08);
    color: var(--error-color);
    border: 1px solid rgba(211, 47, 47, 0.3);
    box-shadow: 0 1px 3px rgba(211, 47, 47, 0.1);
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
    padding: 1.25rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin: 1.5rem 0;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .photo-ids code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-family: monospace;
    font-weight: 500;
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
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    margin-top: 0.5rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.12), 0 2px 6px rgba(0, 0, 0, 0.08);
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
    background: rgba(0, 122, 255, 0.06);
  }

  .dropdown-item:first-child {
    border-radius: 10px 10px 0 0;
  }

  .dropdown-item:last-child {
    border-bottom: none;
    border-radius: 0 0 10px 10px;
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

  .checkbox-group {
    margin-bottom: 1.5rem;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
    font-weight: 400;
    color: var(--text-primary);
    font-size: 0.9375rem;
  }

  .checkbox-input {
    width: 18px;
    height: 18px;
    cursor: pointer;
    accent-color: var(--accent-color);
  }

  .form-group small.warning {
    color: #ff9800;
  }
</style>
