<script>
  import { onMount } from 'svelte';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  let activeTab = 'existing'; // 'existing' or 'new'
  let csrfToken = '';

  // Existing artwork upload state
  let artworkId = '';
  let selectedFiles = [];
  let isPrimary = false;
  let uploadStatus = '';
  let uploadError = '';
  let uploadProgress = [];

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
  });

  // Handle file selection for existing artwork
  function handleFileSelect(event) {
    selectedFiles = Array.from(event.target.files);
    uploadStatus = '';
    uploadError = '';
    uploadProgress = selectedFiles.map(() => ({ status: 'pending', message: '' }));
  }

  // Handle file selection for orphaned photos
  function handleOrphanedFileSelect(event) {
    orphanedFiles = Array.from(event.target.files);
    orphanedStatus = '';
    orphanedError = '';
    orphanedProgress = orphanedFiles.map(() => ({ status: 'pending', message: '' }));
    uploadedPhotoIds = [];
  }

  // Upload photos to existing artwork
  async function uploadToExistingArtwork() {
    if (!artworkId.trim()) {
      uploadError = 'Please enter an artwork ID';
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
          const data = await response.json();
          uploadProgress[i] = { status: 'success', message: 'Uploaded successfully!' };
        } else {
          // Handle authentication errors specially
          if (response.status === 401) {
            uploadProgress[i] = {
              status: 'error',
              message: 'Not logged in. Please log in at /auth/login to upload photos.'
            };
          } else {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            uploadProgress[i] = {
              status: 'error',
              message: error.error || `Upload failed with status ${response.status}`
            };
          }
        }
      } catch (error) {
        uploadProgress[i] = {
          status: 'error',
          message: `Upload failed: ${error.message}`
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
  }

  // Upload orphaned photos
  async function uploadOrphanedPhotos() {
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
          // Handle authentication errors specially
          if (response.status === 401) {
            orphanedProgress[i] = {
              status: 'error',
              message: 'Not logged in. Please log in at /auth/login to upload photos.'
            };
          } else {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            orphanedProgress[i] = {
              status: 'error',
              message: error.error || `Upload failed with status ${response.status}`
            };
          }
        }
      } catch (error) {
        orphanedProgress[i] = {
          status: 'error',
          message: `Upload failed: ${error.message}`
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
  }
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
    <p>Upload photos for an artwork that already exists in the database.</p>

    <form on:submit|preventDefault={uploadToExistingArtwork}>
      <div class="form-group">
        <label for="artwork-id">Artwork ID</label>
        <input
          id="artwork-id"
          type="text"
          bind:value={artworkId}
          placeholder="Enter artwork ID (e.g., A1234567)"
          required
        />
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
                <div class="file-info">{file.name} ({(file.size / 1024).toFixed(1)} KB)</div>
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
                <div class="file-info">{file.name} ({(file.size / 1024).toFixed(1)} KB)</div>
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
    border-bottom: 2px solid #444;
  }

  .tabs button {
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    border-bottom: 3px solid transparent;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s;
    color: #e0e0e0;
  }

  .tabs button:hover {
    background: #2a2a2a;
  }

  .tabs button.active {
    border-bottom-color: #5a9fd4;
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
    color: #e0e0e0;
  }

  .form-group input[type="text"],
  .form-group input[type="file"] {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid #444;
    border-radius: 4px;
    background: #1e1e1e;
    color: #e0e0e0;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="file"]:focus {
    outline: none;
    border-color: #5a9fd4;
  }

  .form-group small {
    display: block;
    margin-top: 0.25rem;
    color: #999;
    font-size: 0.875rem;
  }

  button[type="submit"] {
    padding: 0.75rem 1.5rem;
    background: #5a9fd4;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
  }

  button[type="submit"]:hover:not(:disabled) {
    background: #4a8fc4;
  }

  button[type="submit"]:disabled {
    background: #444;
    color: #666;
    cursor: not-allowed;
  }

  .file-preview {
    padding: 1rem;
    background: #1e1e1e;
    border: 1px solid #444;
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
    background: #252525;
    border-radius: 4px;
    border-left: 3px solid #444;
  }

  .file-info {
    color: #e0e0e0;
    margin-bottom: 0.25rem;
  }

  .status-message {
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
  }

  .status-message.success {
    background: #1e3a1e;
    color: #a8d5a8;
    border: 1px solid #2d5a2d;
  }

  .status-message.error {
    background: #3a1e1e;
    color: #d5a8a8;
    border: 1px solid #5a2d2d;
  }

  .status-pending {
    color: #999;
    font-size: 0.875rem;
    margin-top: 0.25rem;
  }

  .status-uploading {
    color: #5a9fd4;
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
  }

  .status-success {
    color: #6fbf6f;
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: #1e3a1e;
    border-radius: 3px;
    border-left: 3px solid #6fbf6f;
  }

  .status-error {
    color: #d57676;
    font-weight: bold;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: #3a1e1e;
    border-radius: 3px;
    border-left: 3px solid #d57676;
  }

  .photo-ids {
    padding: 1rem;
    background: #1e2a3a;
    border: 1px solid #3a4a5a;
    border-radius: 4px;
    margin: 1rem 0;
  }

  .photo-ids code {
    background: #2a2a2a;
    color: #e0e0e0;
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
  }
</style>
