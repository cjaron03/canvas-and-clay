<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { onMount, onDestroy } from 'svelte';
  import ArtworkDeleteModal from '$lib/components/ArtworkDeleteModal.svelte';
  import ArtworkRestoreButton from '$lib/components/ArtworkRestoreButton.svelte';

  export let data;

  let showDeleteModal = false;
  let showDetails = false;
  let selectedPhoto = null;
  let modalElement;
  let imageErrors = new Set();
  let currentPhotoIndex = 0;

  // Initialize with primary photo if available, otherwise first photo
  $: validPhotos = data.artwork.photos?.filter(p => p && (p.thumbnail_url || p.thumbnail || p.url)) || [];
  
  $: if (validPhotos.length > 0 && currentPhotoIndex >= validPhotos.length) {
    currentPhotoIndex = 0;
  }

  const getThumbnailUrl = (path) => {
    if (!path) return null;
    if (path.startsWith('http')) return path;
    if (!PUBLIC_API_BASE_URL) return null;
    return `${PUBLIC_API_BASE_URL}${path}`;
  };

  const getFullUrl = (photo) => {
    if (!photo) return null;
    if (photo.url) return getThumbnailUrl(photo.url);
    return getThumbnailUrl(photo.thumbnail_url || photo.thumbnail);
  };

  const handleImageError = (photoId) => {
    console.error('image failed to load:', photoId);
    imageErrors = new Set(imageErrors).add(photoId);
  };

  const isImageError = (photoId) => imageErrors.has(photoId);

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Unknown';
    return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  };

  const openDeleteModal = () => showDeleteModal = true;
  const closeDeleteModal = () => showDeleteModal = false;

  const handleDeleteSuccess = (result) => {
    if (result.deletion_type === 'Soft-deleted') window.location.reload();
    else goto('/artworks');
  };

  const handleRestoreSuccess = () => window.location.reload();

  const openPhotoModal = (photo) => selectedPhoto = photo;
  const closePhotoModal = () => selectedPhoto = null;

  const handleModalClick = (e) => {
    if (e.target === modalElement) closePhotoModal();
  };

  const handleModalKeydown = (e) => {
    if (e.key === 'Escape') closePhotoModal();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape' && selectedPhoto) closePhotoModal();
    if (e.key === 'ArrowLeft' && data.artwork.prev_artwork_id) goto(`/artworks/${data.artwork.prev_artwork_id}`);
    if (e.key === 'ArrowRight' && data.artwork.next_artwork_id) goto(`/artworks/${data.artwork.next_artwork_id}`);
  };

  $: artistOwnerId = data.artwork?.artist?.user_id;
  $: canEditArtwork = $auth.isAuthenticated && ($auth.user?.role === 'admin' || ($auth.user?.role === 'artist' && artistOwnerId && String(artistOwnerId) === String($auth.user?.id)));
  $: isSoftDeleted = data.artwork?.is_deleted === true;
  $: canDelete = canEditArtwork && !isSoftDeleted;
  $: canRestore = canEditArtwork && isSoftDeleted;

  onMount(() => {
    window.addEventListener('keydown', handleKeyDown);
  });

  onDestroy(() => {
    if (typeof window !== 'undefined') {
      window.removeEventListener('keydown', handleKeyDown);
    }
  });
</script>

<div class="container">
  <div class="header-nav">
    <a href="/artworks" class="back-link">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      Back to Artworks
    </a>
  </div>

  <div class="artwork-layout">
    <!-- Left Column: Image Viewer -->
    <div class="image-section">
      <div class="main-image-card">
        <div class="image-nav-wrapper">
          {#if data.artwork.prev_artwork_id}
            <a href="/artworks/{data.artwork.prev_artwork_id}" class="nav-arrow prev" title="Previous Artwork">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </a>
          {/if}
          
          {#if validPhotos.length > 0}
            {@const currentPhoto = validPhotos[currentPhotoIndex]}
            {@const photoId = currentPhoto.id || currentPhoto.photo_id}
            
            {#if !isImageError(photoId)}
              <button class="main-image-btn" on:click={() => openPhotoModal(currentPhoto)}>
                <img 
                  src={getFullUrl(currentPhoto)} 
                  alt={data.artwork.title}
                  on:error={() => handleImageError(photoId)}
                />
                <div class="zoom-hint">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
                </div>
              </button>
            {:else}
              <div class="placeholder-large">
                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
                <span>Image unavailable</span>
              </div>
            {/if}
          {:else}
            <div class="placeholder-large">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
              <span>No photos uploaded</span>
            </div>
          {/if}

          {#if data.artwork.next_artwork_id}
            <a href="/artworks/{data.artwork.next_artwork_id}" class="nav-arrow next" title="Next Artwork">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </a>
          {/if}
        </div>
      </div>

      {#if validPhotos.length > 1}
        <div class="thumbnail-strip">
          {#each validPhotos as photo, i}
            <button 
              class="thumb-btn" 
              class:active={i === currentPhotoIndex}
              on:click={() => currentPhotoIndex = i}
            >
              <img src={getThumbnailUrl(photo.thumbnail_url || photo.thumbnail)} alt="Thumbnail" />
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Right Column: Info & Metadata -->
    <div class="info-section">
      <div class="title-header">
        <h1>{data.artwork.title}</h1>
        {#if canEditArtwork}
          <div class="admin-toolbar">
            <a href="/uploads?artwork_id={data.artwork.id}" class="tool-btn" title="Add Photo">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
            </a>
            <a href="/artworks/{data.artwork.id}/edit" class="tool-btn" title="Edit Details">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            </a>
            {#if canDelete}
              <button on:click={openDeleteModal} class="tool-btn delete" title="Delete Artwork">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            {/if}
            {#if canRestore}
              <div class="restore-wrapper">
                <ArtworkRestoreButton artworkId={data.artwork.id} artworkTitle={data.artwork.title} onSuccess={handleRestoreSuccess} />
              </div>
            {/if}
          </div>
        {/if}
      </div>

      <div class="artist-link">
        {#if data.artwork.artist?.id}
          <a href="/artists/{data.artwork.artist.id}">{data.artwork.artist.name}</a>
        {:else}
          <span class="unknown-artist">{data.artwork.artist?.name || 'Unknown Artist'}</span>
        {/if}
      </div>

      <div class="core-meta">
        {#if data.artwork.medium}
          <div class="meta-item">
            <span class="label">Medium</span>
            <span class="value">{data.artwork.medium}</span>
          </div>
        {/if}
        {#if data.artwork.size}
          <div class="meta-item">
            <span class="label">Dimensions</span>
            <span class="value">{data.artwork.size}</span>
          </div>
        {/if}
        {#if data.artwork.date_created}
          <div class="meta-item">
            <span class="label">Created</span>
            <span class="value">{formatDate(data.artwork.date_created)}</span>
          </div>
        {/if}
      </div>

      <div class="details-card">
        <button class="details-toggle" on:click={() => showDetails = !showDetails}>
          <span>Technical Details</span>
          <svg class:rotated={showDetails} xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        </button>
        
        {#if showDetails}
          <div class="details-content">
            <div class="detail-group">
              <span class="detail-label">Artwork ID</span>
              <code class="detail-value">{data.artwork.id}</code>
            </div>
            {#if data.artwork.artist?.id}
              <div class="detail-group">
                <span class="detail-label">Artist ID</span>
                <code class="detail-value">{data.artwork.artist.id}</code>
              </div>
            {/if}
            {#if data.artwork.storage}
              <div class="detail-group">
                <span class="detail-label">Location</span>
                <span class="detail-value">
                  {data.artwork.storage.location}
                  {#if data.artwork.storage.type}({data.artwork.storage.type}){/if}
                </span>
              </div>
              {#if data.artwork.storage.id}
                <div class="detail-group">
                  <span class="detail-label">Storage ID</span>
                  <code class="detail-value">{data.artwork.storage.id}</code>
                </div>
              {/if}
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

{#if selectedPhoto}
  <div class="photo-modal" bind:this={modalElement} on:click={handleModalClick} on:keydown={handleModalKeydown} role="dialog" tabindex="0">
    <button class="photo-modal-close" on:click={closePhotoModal}>×</button>
    <img src={getFullUrl(selectedPhoto)} alt="Full size" class="photo-modal-image" />
  </div>
{/if}

{#if showDeleteModal}
  <ArtworkDeleteModal artworkId={data.artwork.id} artworkTitle={data.artwork.title} onSuccess={handleDeleteSuccess} onCancel={closeDeleteModal} />
{/if}

<style>
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  .header-nav {
    margin-bottom: 2rem;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    transition: color 0.2s;
  }

  .back-link:hover {
    color: var(--text-primary);
  }

  .artwork-layout {
    display: grid;
    grid-template-columns: 1.5fr 1fr;
    gap: 4rem;
    align-items: start;
  }

  /* Image Section */
  .image-section {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .main-image-card {
    position: relative;
    background: var(--bg-secondary);
    border-radius: 12px;
    overflow: hidden;
    min-height: 400px;
    display: flex;
    align-items: center;
    justify-content: center;
    /* Removed border */
    padding: 1rem;
  }

  .image-nav-wrapper {
    position: relative;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .main-image-btn {
    border: none;
    padding: 0;
    background: transparent;
    cursor: zoom-in;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .main-image-btn img {
    max-width: 100%;
    max-height: 80vh; /* Standard max-height */
    width: auto;
    height: auto;
    object-fit: contain;
    display: block;
    border-radius: 4px;
  }

  .zoom-hint {
    position: absolute;
    bottom: 1rem;
    right: 1rem;
    background: rgba(0, 0, 0, 0.6);
    color: white;
    padding: 0.6rem;
    border-radius: 50%;
    opacity: 0;
    transition: opacity 0.2s;
    pointer-events: none;
  }

  .main-image-btn:hover .zoom-hint {
    opacity: 1;
  }

  /* Navigation Arrows - Always Visible */
  .nav-arrow {
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    width: 56px; /* Increased size */
    height: 56px;
    border-radius: 50%;
    background: var(--nav-arrow-bg, rgba(255, 255, 255, 0.8)); /* Theme-aware background */
    color: var(--nav-arrow-color, var(--text-primary)); /* Theme-aware color */
    backdrop-filter: blur(8px); /* Frosted glass effect */
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2); /* Deeper shadow */
    transition: all 0.2s ease;
    z-index: 20;
    opacity: 0.7;
    border: 1px solid var(--nav-arrow-border, rgba(0,0,0,0.05)); /* Theme-aware border */
  }

  .nav-arrow:hover {
    transform: translateY(-50%) scale(1.1);
    background: var(--nav-arrow-hover-bg, white); /* Theme-aware hover background */
    opacity: 1;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
  }

  /* Dark mode overrides (assuming [data-theme='dark'] on :root or html) */
  :global([data-theme='dark']) .nav-arrow {
    --nav-arrow-bg: rgba(30, 30, 30, 0.8);
    --nav-arrow-color: white;
    --nav-arrow-border: rgba(255, 255, 255, 0.1);
  }

  :global([data-theme='dark']) .nav-arrow:hover {
    --nav-arrow-hover-bg: rgb(50, 50, 50);
  }

  .nav-arrow.prev { left: 0; }
  .nav-arrow.next { right: 0; }

  /* Placeholder */
  .placeholder-large {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    color: var(--text-tertiary);
    width: 100%;
    height: 100%;
    min-height: 400px;
  }

  .thumbnail-strip {
    display: flex;
    gap: 0.75rem;
    overflow-x: auto;
    padding-bottom: 0.5rem;
  }

  .thumb-btn {
    width: 80px;
    height: 80px;
    border: 2px solid transparent;
    padding: 0;
    cursor: pointer;
    border-radius: 4px;
    overflow: hidden;
    opacity: 0.7;
    transition: all 0.2s;
  }

  .thumb-btn:hover, .thumb-btn.active {
    opacity: 1;
    border-color: var(--accent-color);
  }

  .thumb-btn img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  /* Info Section */
  .info-section {
    padding-top: 0.5rem;
  }

  .title-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }

  h1 {
    margin: 0;
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1.1;
  }

  .admin-toolbar {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
  }

  .tool-btn {
    padding: 0.6rem;
    color: var(--text-secondary);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .tool-btn:hover {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border-color: var(--accent-color);
  }

  .tool-btn.delete:hover {
    color: var(--error-color);
    background: rgba(220, 38, 38, 0.1);
    border-color: var(--error-color);
  }

  .artist-link {
    margin-bottom: 2rem;
  }

  .artist-link a {
    font-size: 1.25rem;
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
  }

  .artist-link a:hover {
    text-decoration: underline;
  }

  .core-meta {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-bottom: 2.5rem;
    padding-bottom: 2.5rem;
    border-bottom: 1px solid var(--border-color);
  }

  .meta-item {
    display: grid;
    grid-template-columns: 120px 1fr;
    align-items: baseline;
  }

  .meta-item .label {
    color: var(--text-tertiary);
    font-size: 0.9rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .meta-item .value {
    color: var(--text-primary);
    font-size: 1.1rem;
  }

  /* Details Card */
  .details-card {
    background: var(--bg-secondary);
    border-radius: 8px;
    overflow: hidden;
  }

  .details-toggle {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.25rem;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-secondary);
    font-weight: 500;
    font-size: 0.95rem;
    transition: background 0.2s;
  }

  .details-toggle:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .details-toggle svg {
    transition: transform 0.2s;
  }

  .details-toggle svg.rotated {
    transform: rotate(180deg);
  }

  .details-content {
    padding: 0 1.25rem 1.25rem 1.25rem;
    border-top: 1px solid var(--border-color);
    background: var(--bg-tertiary);
  }

  .detail-group {
    display: flex;
    justify-content: space-between;
    padding: 0.75rem 0;
    border-bottom: 1px solid var(--border-color);
    font-size: 0.9rem;
  }

  .detail-group:last-child {
    border-bottom: none;
  }

  .detail-label {
    color: var(--text-tertiary);
  }

  .detail-value {
    color: var(--text-primary);
    font-family: monospace;
  }

  /* Modal */
  .photo-modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.95);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: zoom-out;
  }

  .photo-modal-image {
    max-width: 95vw;
    max-height: 95vh;
    object-fit: contain;
    box-shadow: 0 0 40px rgba(0,0,0,0.5);
  }

  .photo-modal-close {
    position: absolute;
    top: 2rem;
    right: 2rem;
    background: rgba(255, 255, 255, 0.1);
    border: none;
    color: white;
    font-size: 2rem;
    width: 3.5rem;
    height: 3.5rem;
    border-radius: 50%;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s;
  }

  .photo-modal-close:hover {
    background: rgba(255, 255, 255, 0.2);
  }

  @media (max-width: 900px) {
    .artwork-layout {
      grid-template-columns: 1fr;
      gap: 2rem;
    }

    h1 {
      font-size: 2rem;
    }

    .title-header {
      flex-direction: column-reverse;
      gap: 1rem;
    }

    .admin-toolbar {
      width: 100%;
      justify-content: flex-end;
    }
  }
</style>