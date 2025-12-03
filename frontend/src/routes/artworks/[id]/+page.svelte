<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
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
    // Fallback to thumbnail if full url not available (should be rare with new backend)
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
  };

  $: artistOwnerId = data.artwork?.artist?.user_id;
  $: canEditArtwork = $auth.isAuthenticated && ($auth.user?.role === 'admin' || ($auth.user?.role === 'artist' && artistOwnerId && String(artistOwnerId) === String($auth.user?.id)));
  $: isSoftDeleted = data.artwork?.is_deleted === true;
  $: canDelete = canEditArtwork && !isSoftDeleted;
  $: canRestore = canEditArtwork && isSoftDeleted;

  onMount(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
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
      <div class="main-image-container">
        {#if data.artwork.prev_artwork_id}
          <a href="/artworks/{data.artwork.prev_artwork_id}" class="nav-arrow prev" title="Previous Artwork">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
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
                on:error={(e) => handleImageError(photoId, e)}
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
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </a>
        {/if}
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
      <div class="title-group">
        {#if canEditArtwork}
          <div class="admin-toolbar">
            <a href="/uploads?artwork_id={data.artwork.id}" class="tool-btn" title="Add Photo">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
            </a>
            <a href="/artworks/{data.artwork.id}/edit" class="tool-btn" title="Edit Details">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            </a>
            {#if canDelete}
              <button on:click={openDeleteModal} class="tool-btn delete" title="Delete Artwork">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            {/if}
            {#if canRestore}
              <div class="restore-wrapper">
                <ArtworkRestoreButton artworkId={data.artwork.id} artworkTitle={data.artwork.title} onSuccess={handleRestoreSuccess} />
              </div>
            {/if}
          </div>
        {/if}
        <h1>{data.artwork.title}</h1>
        <div class="artist-link">
          {#if data.artwork.artist?.id}
            <a href="/artists/{data.artwork.artist.id}">{data.artwork.artist.name}</a>
          {:else}
            <span class="unknown-artist">{data.artwork.artist?.name || 'Unknown Artist'}</span>
          {/if}
        </div>
      </div>

      <div class="core-meta">
        {#if data.artwork.medium}
          <div class="meta-row">
            <span class="label">Medium</span>
            <span class="value">{data.artwork.medium}</span>
          </div>
        {/if}
        {#if data.artwork.size}
          <div class="meta-row">
            <span class="label">Dimensions</span>
            <span class="value">{data.artwork.size}</span>
          </div>
        {/if}
        {#if data.artwork.date_created}
          <div class="meta-row">
            <span class="label">Date</span>
            <span class="value">{formatDate(data.artwork.date_created)}</span>
          </div>
        {/if}
      </div>

      <div class="details-toggle">
        <button on:click={() => showDetails = !showDetails} class="toggle-btn">
          {showDetails ? 'Hide details' : 'Show details'}
          <svg class:rotated={showDetails} xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        </button>
      </div>

      {#if showDetails}
        <div class="extended-meta">
          <div class="meta-group">
            <h4>System IDs</h4>
            <div class="meta-pair"><span>Artwork ID:</span> <code>{data.artwork.id}</code></div>
            {#if data.artwork.artist?.id}
              <div class="meta-pair"><span>Artist ID:</span> <code>{data.artwork.artist.id}</code></div>
            {/if}
          </div>
          
          {#if data.artwork.storage}
            <div class="meta-group">
              <h4>Location</h4>
              <div class="meta-pair"><span>Location:</span> {data.artwork.storage.location}</div>
              {#if data.artwork.storage.type}
                <div class="meta-pair"><span>Type:</span> {data.artwork.storage.type}</div>
              {/if}
              {#if data.artwork.storage.id}
                <div class="meta-pair"><span>Storage ID:</span> <code>{data.artwork.storage.id}</code></div>
              {/if}
            </div>
          {/if}
        </div>
      {/if}
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

  .main-image-container {
    width: 100%;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
    aspect-ratio: 1; /* Default aspect, allows intrinsic sizing via img */
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
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
    max-height: 80vh; /* Prevent overly tall images */
    object-fit: contain;
    display: block;
  }

  .zoom-hint {
    position: absolute;
    bottom: 1rem;
    right: 1rem;
    background: rgba(0, 0, 0, 0.6);
    color: white;
    padding: 0.5rem;
    border-radius: 50%;
    opacity: 0;
    transition: opacity 0.2s;
    pointer-events: none;
  }

  .main-image-btn:hover .zoom-hint {
    opacity: 1;
  }

  .nav-arrow {
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    background: rgba(255, 255, 255, 0.8);
    color: var(--text-primary);
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    opacity: 0;
    transition: all 0.2s;
    z-index: 10;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }

  .main-image-container:hover .nav-arrow {
    opacity: 1;
  }

  .nav-arrow:hover {
    background: white;
    transform: translateY(-50%) scale(1.1);
  }

  .nav-arrow.prev { left: 1rem; }
  .nav-arrow.next { right: 1rem; }

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
    padding-top: 1rem;
  }

  .title-group {
    margin-bottom: 2rem;
    position: relative;
  }

  .admin-toolbar {
    display: flex;
    gap: 0.5rem;
    position: absolute;
    top: 0;
    right: 0;
  }

  .tool-btn {
    padding: 0.5rem;
    color: var(--text-secondary);
    background: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .tool-btn:hover {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border-color: var(--border-color);
  }

  .tool-btn.delete:hover {
    color: var(--error-color);
    background: rgba(220, 38, 38, 0.1);
  }

  h1 {
    font-size: 2.5rem;
    font-weight: 700;
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    line-height: 1.2;
    padding-right: 6rem; /* Space for toolbar */
  }

  .artist-link a {
    font-size: 1.25rem;
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    border-bottom: 1px solid transparent;
    transition: all 0.2s;
  }

  .artist-link a:hover {
    color: var(--accent-color);
    border-bottom-color: var(--accent-color);
  }

  .unknown-artist {
    font-size: 1.25rem;
    color: var(--text-tertiary);
    font-style: italic;
  }

  .core-meta {
    margin-bottom: 2rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .meta-row {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    font-size: 1rem;
  }

  .meta-row .label {
    color: var(--text-tertiary);
    font-weight: 500;
    min-width: 100px;
  }

  .meta-row .value {
    color: var(--text-primary);
  }

  .details-toggle {
    margin-bottom: 1rem;
  }

  .toggle-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent-color);
    font-size: 0.9rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }

  .toggle-btn svg {
    transition: transform 0.2s;
  }

  .toggle-btn svg.rotated {
    transform: rotate(180deg);
  }

  .extended-meta {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: 8px;
    font-size: 0.9rem;
  }

  .meta-group {
    margin-bottom: 1.5rem;
  }

  .meta-group:last-child {
    margin-bottom: 0;
  }

  .meta-group h4 {
    margin: 0 0 0.75rem 0;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.5px;
  }

  .meta-pair {
    margin-bottom: 0.5rem;
    display: flex;
    justify-content: space-between;
  }

  .meta-pair span {
    color: var(--text-tertiary);
  }

  .meta-pair code {
    background: var(--bg-tertiary);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.85em;
  }

  /* Modal Styles */
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
    top: 1rem;
    right: 1rem;
    background: rgba(255, 255, 255, 0.1);
    border: none;
    color: white;
    font-size: 2rem;
    width: 3rem;
    height: 3rem;
    border-radius: 50%;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s;
  }

  .photo-modal-close:hover {
    background: rgba(255, 255, 255, 0.3);
  }

  @media (max-width: 900px) {
    .artwork-layout {
      grid-template-columns: 1fr;
      gap: 2rem;
    }

    h1 {
      font-size: 2rem;
      padding-right: 0;
    }

    .admin-toolbar {
      position: relative;
      justify-content: flex-end;
      margin-bottom: 1rem;
    }
  }
</style>
