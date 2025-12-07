<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { onMount } from 'svelte';
  import ArtistDeleteModal from '$lib/components/ArtistDeleteModal.svelte';

  export let data;

  let showDeleteModal = false;
  let selectedPhoto = null;
  let modalElement;

  const getThumbnailUrl = (path) => {
    if (!path) return null;
    if (path.startsWith('http')) return path;
    return `${PUBLIC_API_BASE_URL}${path}`;
  };

  const openDeleteModal = () => {
    showDeleteModal = true;
  };

  const closeDeleteModal = () => {
    showDeleteModal = false;
  };

  const handleDeleteSuccess = () => {
    showDeleteModal = false;
    // Use hard navigation to force fresh data load
    window.location.href = '/artists';
  };

  const closePhotoModal = () => {
    selectedPhoto = null;
  };

  const handleModalClick = (e) => {
    if (e.target === modalElement) {
      closePhotoModal();
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape' && selectedPhoto) {
      closePhotoModal();
    }
  };

  $: artistOwnerId = data.artist?.user_id;
  $: canUpload =
    $auth.isAuthenticated &&
    ($auth.user?.role === 'admin' ||
      ($auth.user?.role === 'artist' &&
        artistOwnerId &&
        String(artistOwnerId) === String($auth.user?.id)));
  $: canEditArtist = canUpload;
  $: canDeleteArtist = $auth.isAuthenticated && $auth.user?.role === 'admin';

  onMount(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  });
</script>

<div class="container">
  <div class="header">
    <a href="/artists" class="back-link">
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      Back to Artists
    </a>
    {#if canEditArtist}
      <div class="actions">
        <a href="/artists/{data.artist.artist_id}/edit" class="btn-secondary">Edit</a>
        {#if canDeleteArtist}
          <button on:click={openDeleteModal} class="btn-danger">Delete</button>
        {/if}
      </div>
    {/if}
  </div>

  <div class="artist-detail">
    <div class="artworks-section">
      {#if data.artworksError}
        <div class="artworks-error">{data.artworksError}</div>
      {:else if data.artworks && data.artworks.length > 0}
        <div class="artwork-grid">
          {#each data.artworks as artwork}
            {@const thumbnailPath = artwork.primary_photo?.thumbnail_url || artwork.primary_photo?.thumbnail}
            <a href="/artworks/{artwork.id}" class="artwork-card">
              <div class="artwork-thumbnail">
                {#if thumbnailPath}
                  <img src={getThumbnailUrl(thumbnailPath)} alt={artwork.title || 'Artwork thumbnail'} />
                {:else}
                  <div class="no-image">No Image</div>
                {/if}
              </div>
              <div class="artwork-info">
                <h3>{artwork.title || 'Untitled'}</h3>
                <p class="artwork-id"><code>{artwork.id}</code></p>
                {#if artwork.medium}
                  <p class="medium">{artwork.medium}</p>
                {/if}
                {#if artwork.storage?.location}
                  <p class="storage">Storage: {artwork.storage.location}</p>
                {/if}
              </div>
            </a>
          {/each}
        </div>
      {:else}
        <div class="no-artworks">
          <p>No artworks recorded for this artist yet.</p>
        </div>
      {/if}
    </div>

    <div class="info-section">
      <div class="artist-thumbnail">
        {#if data.artist.photo_thumbnail || data.artist.photo_url}
          {@const artistPhoto = data.artist.photo_thumbnail || data.artist.photo_url}
          <img
            src={getThumbnailUrl(artistPhoto)}
            alt={`${data.artist.artist_fname || ''} ${data.artist.artist_lname || ''}`.trim() || 'Artist thumbnail'}
          />
        {:else}
          <div class="no-image-placeholder">No Image</div>
        {/if}
      </div>

      <h1>{[data.artist.artist_fname, data.artist.artist_lname].filter(Boolean).join(' ') || 'Unknown Artist'}</h1>

      <div class="metadata">
        <div class="meta-item">
          <span class="meta-label">Artist ID</span>
          <span class="meta-value"><code>{data.artist.artist_id}</code></span>
        </div>

        {#if data.artist.artist_bio}
          <div class="meta-item">
            <span class="meta-label">Artist Bio</span>
            <p class="meta-value bio">{data.artist.artist_bio}</p>
          </div>
        {/if}

        {#if data.artist.mediums && data.artist.mediums.length > 0}
          <div class="meta-item">
            <span class="meta-label">Mediums</span>
            <div class="meta-value list">
              <ul>
                {#each data.artist.mediums as medium}
                  <li>{medium}</li>
                {/each}
              </ul>
            </div>
          </div>
        {/if}

        {#if data.artist.storage_locations && data.artist.storage_locations.length > 0}
          <div class="meta-item">
            <span class="meta-label">Storage Locations</span>
            <div class="meta-value list">
              <ul>
                {#each data.artist.storage_locations as location}
                  <li>
                    <span class="storage-location-name">{location.location || 'Unknown location'}</span>
                    {#if location.type}
                      <span class="storage-type">({location.type})</span>
                    {/if}
                    {#if location.id}
                      <span class="storage-id"><code>{location.id}</code></span>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          </div>
        {/if}

        {#if data.artist.email}
          <div class="meta-item">
            <span class="meta-label">Artist Email</span>
            <span class="meta-value">{data.artist.email}</span>
          </div>
        {/if}

        {#if data.artist.artist_site}
          <div class="meta-item">
            <span class="meta-label">Artist Site</span>
            <span class="meta-value">
              <a href={data.artist.artist_site} target="_blank" rel="noopener noreferrer">
                {data.artist.artist_site}
              </a>
            </span>
          </div>
        {/if}

        {#if data.artist.artist_phone}
          <div class="meta-item">
            <span class="meta-label">Artist Phone</span>
            <span class="meta-value">{data.artist.artist_phone}</span>
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

{#if selectedPhoto}
  {@const fullPhotoUrl = selectedPhoto.url
    ? getThumbnailUrl(selectedPhoto.url)
    : selectedPhoto.thumbnail_url || selectedPhoto.thumbnail
      ? getThumbnailUrl(selectedPhoto.thumbnail_url || selectedPhoto.thumbnail)
      : null}
  <div
    class="photo-modal"
    bind:this={modalElement}
    on:click={handleModalClick}
    role="dialog"
    aria-modal="true"
    aria-label="Full size image view"
    tabindex="-1"
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
          alt={selectedPhoto.filename || 'Full size artist photo'}
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

{#if showDeleteModal}
  <ArtistDeleteModal
    artistId={data.artist.artist_id}
    artistName={`${data.artist.artist_fname || ''} ${data.artist.artist_lname || ''}`.trim() || 'Unknown Artist'}
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
    display: flex;
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

  .error {
    padding: 1rem;
    background: var(--error-color);
    color: white;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .artist-detail {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 2rem;
  }

  .artworks-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 1.5rem;
    min-height: 400px;
    display: flex;
    flex-direction: column;
  }

  .artworks-error {
    padding: 1rem;
    background: var(--error-color);
    color: white;
    border-radius: 4px;
  }

  .artwork-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 350px));
    gap: 1.5rem;
    justify-content: center;
  }

  .artwork-card {
    background: var(--bg-tertiary);
    border-radius: 8px;
    overflow: hidden;
    text-decoration: none;
    color: inherit;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
  }

  .artwork-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
  }

  .artwork-thumbnail {
    width: 100%;
    height: 200px;
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  .artwork-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .no-image {
    color: var(--text-tertiary);
    font-size: 0.875rem;
  }

  .artwork-info {
    padding: 1rem;
  }

  .artwork-info h3 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.1rem;
  }

  .artwork-id {
    margin: 0 0 0.5rem 0;
    font-size: 0.75rem;
  }

  .artwork-id code {
    background: var(--bg-secondary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
  }

  .medium,
  .storage {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0 0 0.25rem 0;
  }

  .no-artworks {
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
  }

  .no-artworks p {
    margin: 0;
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
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  h1 {
    margin: 0 0 1.5rem 0;
    color: var(--text-primary);
    font-size: 1.75rem;
  }

  .artist-thumbnail {
    width: 100%;
    aspect-ratio: 1.5 / 1;
    border-radius: 8px;
    overflow: hidden;
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .artist-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
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

  .meta-value.bio {
    margin: 0;
    white-space: pre-wrap;
  }

  .meta-value.list ul {
    margin: 0;
    padding-left: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .storage-location-name {
    font-weight: 600;
  }

  .storage-type {
    color: var(--text-tertiary);
    font-size: 0.875rem;
    margin-left: 0.25rem;
  }

  .storage-id {
    margin-left: 0.5rem;
  }

  .actions-bottom {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border-color);
  }

  @media (max-width: 1024px) {
    .artist-detail {
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
