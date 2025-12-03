<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import ArtworkDeleteModal from '$lib/components/ArtworkDeleteModal.svelte';
  import ArtworkRestoreButton from '$lib/components/ArtworkRestoreButton.svelte';

  export let data;

  let showDeleteModal = false;
  let selectedPhoto = null;
  let modalElement;
  let imageErrors = new Set();

  const getThumbnailUrl = (path) => {
    if (!path) return null;
    if (path.startsWith('http')) return path;
    if (!PUBLIC_API_BASE_URL) {
      console.warn('PUBLIC_API_BASE_URL is not set, image may not load');
      return null;
    }
    return `${PUBLIC_API_BASE_URL}${path}`;
  };

  const handleImageError = (photoId, event) => {
    console.error('image failed to load for photo:', photoId, event.target.src);
    imageErrors = new Set(imageErrors).add(photoId);
  };

  const isImageError = (photoId) => {
    return imageErrors.has(photoId);
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Unknown';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
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
      // For soft delete, reload the page to show restore button
      window.location.reload();
    } else {
      // For hard delete or force delete, redirect to artworks list
      goto('/artworks');
    }
  };

  const handleRestoreSuccess = () => {
    // Reload page to show updated artwork state
    window.location.reload();
  };

  const openPhotoModal = (photo) => {
    selectedPhoto = photo;
  };

  const closePhotoModal = () => {
    selectedPhoto = null;
  };

  const handleModalClick = (e) => {
    // Close modal if clicking outside the image
    if (e.target === modalElement) {
      closePhotoModal();
    }
  };

  const handleModalKeydown = (event) => {
    if (event.key === 'Escape') {
      closePhotoModal();
    }
    if ((event.key === 'Enter' || event.key === ' ') && event.target === modalElement) {
      event.preventDefault();
      closePhotoModal();
    }
  };

  const handleKeyDown = (e) => {
    // Close modal on ESC key
    if (e.key === 'Escape' && selectedPhoto) {
      closePhotoModal();
    }
  };

  $: artistOwnerId = data.artwork?.artist?.user_id;
  $: canUpload =
    $auth.isAuthenticated &&
    ($auth.user?.role === 'admin' ||
      ($auth.user?.role === 'artist' && artistOwnerId && String(artistOwnerId) === String($auth.user?.id)));
  $: canEditArtwork =
    $auth.isAuthenticated &&
    ($auth.user?.role === 'admin' ||
      ($auth.user?.role === 'artist' && artistOwnerId && String(artistOwnerId) === String($auth.user?.id)));
  $: isSoftDeleted = data.artwork?.is_deleted === true;
  $: canDelete = canEditArtwork && !isSoftDeleted;
  $: canRestore = canEditArtwork && isSoftDeleted;

  onMount(() => {
    // Add global keydown listener for ESC key
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  });
</script>

<div class="container">
    <div class="header">
      <a href="/artworks" class="back-link">← Back to Artworks</a>
      {#if canEditArtwork}
        <div class="actions">
          <a href="/artworks/{data.artwork.id}/edit" class="btn-secondary">Edit</a>
          {#if canDelete}
            <button on:click={openDeleteModal} class="btn-danger">Delete</button>
          {/if}
          {#if canRestore}
            <ArtworkRestoreButton
              artworkId={data.artwork.id}
              artworkTitle={data.artwork.title}
              onSuccess={handleRestoreSuccess}
            />
          {/if}
        </div>
      {/if}
    </div>

  <div class="artwork-detail">
    <div class="photos-section">
      {#if data.artwork.photos && Array.isArray(data.artwork.photos) && data.artwork.photos.length > 0}
        {@const validPhotos = data.artwork.photos.filter(p => p && typeof p === 'object' && (p.thumbnail_url || p.thumbnail || p.url))}
        {#if validPhotos.length > 0}
          <div class="photo-gallery">
            {#each validPhotos as photo}
              {@const thumbnailUrl = photo.thumbnail_url || photo.thumbnail}
              {@const mainImageUrl = photo.url}
              {@const photoId = photo.id || photo.photo_id}
              {@const displayUrl = thumbnailUrl || mainImageUrl}
              {#if displayUrl}
                <button
                  type="button"
                  class="photo-item"
                  on:click={() => openPhotoModal(photo)}
                  disabled={isImageError(photoId)}
                >
                  {#if !isImageError(photoId)}
                    <img
                      src={getThumbnailUrl(displayUrl)}
                      alt={photo.filename || 'Artwork photo'}
                      on:error={(e) => handleImageError(photoId, e)}
                      on:load={() => {
                        const newErrors = new Set(imageErrors);
                        newErrors.delete(photoId);
                        imageErrors = newErrors;
                      }}
                    />
                    <div class="photo-overlay">
                      <span>View Full Size</span>
                    </div>
                  {:else}
                    <div class="no-image-placeholder">
                      Image failed to load
                    </div>
                  {/if}
                </button>
              {/if}
            {/each}
          </div>
        {:else}
          <div class="no-photos">
            <p>No photos available for this artwork</p>
            {#if canUpload}
              <a href="/uploads?artwork_id={data.artwork.id}" class="btn-primary">Upload Photo</a>
            {/if}
          </div>
        {/if}
      {:else}
        <div class="no-photos">
          <p>No photos available for this artwork</p>
          {#if canUpload}
            <a href="/uploads?artwork_id={data.artwork.id}" class="btn-primary">Upload Photo</a>
          {/if}
        </div>
      {/if}
    </div>

    <div class="info-section">
      <h1>{data.artwork.title}</h1>

      <div class="metadata">
        <div class="meta-item">
          <span class="meta-label">Artwork ID</span>
          <span class="meta-value"><code>{data.artwork.id}</code></span>
        </div>

        <div class="meta-item">
          <span class="meta-label">Artist</span>
          <span class="meta-value">{data.artwork.artist?.name || 'Unknown Artist'}</span>
        </div>

        {#if data.artwork.artist?.id}
          <div class="meta-item">
            <span class="meta-label">Artist ID</span>
            <span class="meta-value"><code>{data.artwork.artist.id}</code></span>
          </div>
        {/if}

        {#if data.artwork.medium}
          <div class="meta-item">
            <span class="meta-label">Medium</span>
            <span class="meta-value">{data.artwork.medium}</span>
          </div>
        {/if}

        {#if data.artwork.size}
          <div class="meta-item">
            <span class="meta-label">Size</span>
            <span class="meta-value">{data.artwork.size}</span>
          </div>
        {/if}

        {#if data.artwork.date_created}
          <div class="meta-item">
            <span class="meta-label">Date Created</span>
            <span class="meta-value">{formatDate(data.artwork.date_created)}</span>
          </div>
        {/if}

        {#if data.artwork.storage}
          <div class="meta-item">
            <span class="meta-label">Storage Location</span>
            <span class="meta-value">
              {data.artwork.storage.location}
              {#if data.artwork.storage.type}
                <span class="storage-type">({data.artwork.storage.type})</span>
              {/if}
            </span>
          </div>

          {#if data.artwork.storage.id}
            <div class="meta-item">
              <span class="meta-label">Storage ID</span>
              <span class="meta-value"><code>{data.artwork.storage.id}</code></span>
            </div>
          {/if}
        {/if}

        {#if data.artwork.photos && data.artwork.photos.length > 0}
          <div class="meta-item">
            <span class="meta-label">Photos</span>
            <span class="meta-value">{data.artwork.photos.length} photo{data.artwork.photos.length === 1 ? '' : 's'}</span>
          </div>
        {/if}
      </div>

      {#if canUpload}
        <div class="actions-bottom">
          <a href="/uploads?artwork_id={data.artwork.id}" class="btn-primary">Add Photo</a>
        </div>
      {/if}
    </div>
  </div>
</div>

<!-- Photo Modal -->
{#if selectedPhoto}
  {@const fullPhotoUrl = selectedPhoto.url ? getThumbnailUrl(selectedPhoto.url) : (selectedPhoto.thumbnail_url || selectedPhoto.thumbnail ? getThumbnailUrl(selectedPhoto.thumbnail_url || selectedPhoto.thumbnail) : null)}
  <div
    class="photo-modal"
    bind:this={modalElement}
    on:click={handleModalClick}
    on:keydown={handleModalKeydown}
    role="dialog"
    aria-modal="true"
    aria-label="Full size image view"
    tabindex="0"
  >
    <div class="photo-modal-content">
      <button
        class="photo-modal-close"
        on:click={closePhotoModal}
        aria-label="Close image view"
      >
        ×
      </button>
      {#if fullPhotoUrl}
        <img
          src={fullPhotoUrl}
          alt={selectedPhoto.filename || 'Full size artwork photo'}
          class="photo-modal-image"
        />
      {:else}
        <div class="photo-modal-placeholder">No image available</div>
      {/if}
      {#if selectedPhoto.filename}
        <div class="photo-modal-caption">{selectedPhoto.filename}</div>
      {/if}
    </div>
  </div>
{/if}

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
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
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

  .actions {
    display: flex;
    gap: 1rem;
    align-items: center;
  }

  .btn-primary {
    padding: 0.5rem 1rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-primary:hover {
    background: var(--accent-hover);
  }

  .btn-secondary {
    padding: 0.5rem 1rem;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
  }

  .btn-danger {
    padding: 0.5rem 1rem;
    background: var(--error-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-danger:hover:not(:disabled) {
    background: #b71c1c;
  }

  .btn-secondary:disabled,
  .btn-danger:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .artwork-detail {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 2rem;
  }

  .photos-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 1.5rem;
  }

  .photo-gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
  }

  .photo-item {
    position: relative;
    aspect-ratio: 1;
    border-radius: 8px;
    overflow: hidden;
    cursor: pointer;
    display: block;
    width: 100%;
    border: none;
    padding: 0;
    background: transparent;
  }

  .photo-item:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }

  .photo-item img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    transition: transform 0.2s;
  }

  .photo-item:hover img {
    transform: scale(1.05);
  }

  .photo-overlay {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.2s;
  }

  .photo-item:hover .photo-overlay {
    opacity: 1;
  }

  .photo-overlay span {
    color: white;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .no-photos {
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
  }

  .no-photos p {
    margin: 0 0 1rem 0;
  }

  .no-image-placeholder {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-secondary);
    color: var(--text-tertiary);
    font-size: 0.875rem;
  }

  .info-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 1.5rem;
  }

  h1 {
    margin: 0 0 1.5rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
  }

  .metadata {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .meta-item {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-color);
  }

  .meta-item:last-child {
    border-bottom: none;
    padding-bottom: 0;
  }

  .meta-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: var(--text-secondary);
    font-weight: 600;
    letter-spacing: 0.5px;
    margin-bottom: 0.25rem;
  }

  .meta-value {
    color: var(--text-primary);
    font-size: 1rem;
    line-height: 1.5;
  }

  .meta-value code {
    background: var(--bg-secondary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
    font-size: 0.875rem;
  }

  .storage-type {
    color: var(--text-tertiary);
    font-size: 0.875rem;
  }

  .actions-bottom {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border-color);
  }

  @media (max-width: 1024px) {
    .artwork-detail {
      grid-template-columns: 1fr;
    }
  }

  .photo-modal {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 2rem;
    cursor: pointer;
  }

  .photo-modal-content {
    position: relative;
    max-width: 90vw;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    cursor: default;
  }

  .photo-modal-close {
    position: absolute;
    top: -2.5rem;
    right: 0;
    background: rgba(255, 255, 255, 0.2);
    color: white;
    border: none;
    border-radius: 50%;
    width: 2.5rem;
    height: 2.5rem;
    font-size: 1.5rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s;
    z-index: 1001;
  }

  .photo-modal-close:hover {
    background: rgba(255, 255, 255, 0.3);
  }

  .photo-modal-image {
    max-width: 100%;
    max-height: 85vh;
    object-fit: contain;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  }

  .photo-modal-placeholder {
    padding: 4rem;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border-radius: 8px;
    font-size: 1.125rem;
  }

  .photo-modal-caption {
    margin-top: 1rem;
    color: white;
    text-align: center;
    font-size: 0.875rem;
    opacity: 0.9;
  }

  @media (max-width: 768px) {
    .header {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .photo-gallery {
      grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    }

    .photo-modal {
      padding: 1rem;
    }

    .photo-modal-close {
      top: -3rem;
      width: 2rem;
      height: 2rem;
      font-size: 1.25rem;
    }

    .photo-modal-image {
      max-height: 80vh;
    }
  }
</style>
