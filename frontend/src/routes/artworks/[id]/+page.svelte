<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';

  export let data;

  let deleteConfirm = false;
  let deleteError = null;
  let isDeleting = false;

  const getThumbnailUrl = (path) => {
    if (!path) return null;
    if (path.startsWith('http')) return path;
    return `${PUBLIC_API_BASE_URL}${path}`;
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Unknown';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  };

  const handleDelete = async () => {
    if (!deleteConfirm) {
      deleteConfirm = true;
      return;
    }

    isDeleting = true;
    deleteError = null;

    try {
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/artworks/${data.artwork.id}`,
        {
          method: 'DELETE',
          headers: {
            'X-CSRFToken': $auth.csrfToken
          },
          credentials: 'include'
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete artwork');
      }

      // Redirect to artworks list after successful deletion
      goto('/artworks');
    } catch (err) {
      deleteError = err.message;
      isDeleting = false;
      deleteConfirm = false;
    }
  };

  const cancelDelete = () => {
    deleteConfirm = false;
  };
</script>

<div class="container">
  <div class="header">
    <a href="/artworks" class="back-link">← Back to Artworks</a>
    {#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
      <div class="actions">
        <a href="/artworks/{data.artwork.id}/edit" class="btn-secondary">Edit</a>
        {#if !deleteConfirm}
          <button on:click={handleDelete} class="btn-danger">Delete</button>
        {:else}
          <div class="delete-confirm">
            <span>Are you sure?</span>
            <button on:click={handleDelete} class="btn-danger" disabled={isDeleting}>
              {isDeleting ? 'Deleting...' : 'Confirm'}
            </button>
            <button on:click={cancelDelete} class="btn-secondary" disabled={isDeleting}>Cancel</button>
          </div>
        {/if}
      </div>
    {/if}
  </div>

  {#if deleteError}
    <div class="error">{deleteError}</div>
  {/if}

  <div class="artwork-detail">
    <div class="photos-section">
      {#if data.artwork.photos && data.artwork.photos.length > 0}
        <div class="photo-gallery">
          {#each data.artwork.photos as photo}
            <a
              href={getThumbnailUrl(photo.url)}
              target="_blank"
              rel="noopener noreferrer"
              class="photo-item"
            >
              <img
                src={getThumbnailUrl(photo.thumbnail)}
                alt={photo.filename}
              />
              <div class="photo-overlay">
                <span>View Full Size</span>
              </div>
            </a>
          {/each}
        </div>
      {:else}
        <div class="no-photos">
          <p>No photos available for this artwork</p>
          {#if $auth.isAuthenticated}
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

      {#if $auth.isAuthenticated}
        <div class="actions-bottom">
          <a href="/uploads?artwork_id={data.artwork.id}" class="btn-primary">Add Photo</a>
        </div>
      {/if}
    </div>
  </div>
</div>

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
    color: #5a9fd4;
    text-decoration: none;
    transition: color 0.2s;
  }

  .back-link:hover {
    color: #4a8fc4;
  }

  .actions {
    display: flex;
    gap: 1rem;
    align-items: center;
  }

  .delete-confirm {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    padding: 0.5rem 1rem;
    background: #2a2a2a;
    border-radius: 4px;
  }

  .delete-confirm span {
    color: #ff6b6b;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .btn-primary {
    padding: 0.5rem 1rem;
    background: #5a9fd4;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-primary:hover {
    background: #4a8fc4;
  }

  .btn-secondary {
    padding: 0.5rem 1rem;
    background: #444;
    color: #e0e0e0;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s;
  }

  .btn-secondary:hover:not(:disabled) {
    background: #555;
  }

  .btn-danger {
    padding: 0.5rem 1rem;
    background: #d32f2f;
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
    background: #d32f2f;
    color: white;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .artwork-detail {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 2rem;
  }

  .photos-section {
    background: #2a2a2a;
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
    color: #999;
  }

  .no-photos p {
    margin: 0 0 1rem 0;
  }

  .info-section {
    background: #2a2a2a;
    border-radius: 8px;
    padding: 1.5rem;
  }

  h1 {
    margin: 0 0 1.5rem 0;
    color: #e0e0e0;
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
    gap: 0.25rem;
  }

  .meta-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #999;
    font-weight: 500;
    letter-spacing: 0.5px;
  }

  .meta-value {
    color: #e0e0e0;
    font-size: 1rem;
  }

  .meta-value code {
    background: #1e1e1e;
    color: #5a9fd4;
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
    font-size: 0.875rem;
  }

  .storage-type {
    color: #777;
    font-size: 0.875rem;
  }

  .actions-bottom {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid #444;
  }

  @media (max-width: 1024px) {
    .artwork-detail {
      grid-template-columns: 1fr;
    }
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
  }
</style>
