<script>
  import { onMount } from 'svelte';
  import { auth } from '$lib/stores/auth';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import ArtworkDeleteModal from '$lib/components/ArtworkDeleteModal.svelte';
  import ArtworkRestoreButton from '$lib/components/ArtworkRestoreButton.svelte';

  let artworks = [];
  let loading = true;
  let loadError = '';
  let showDeleteModal = false;
  let selectedArtwork = null;

  const fetchMyArtworks = async () => {
    loading = true;
    loadError = '';
    try {
      const isArtist = $auth.user?.role === 'artist';
      const params = isArtist
        ? 'owned=true&include_deleted=true&per_page=200'
        : 'include_deleted=true&per_page=200'; // Admins see all artworks

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks?${params}`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      if (response.status === 401 || response.status === 403) {
        loadError = 'You need an artist or admin account to view this page.';
        return;
      }
      if (!response.ok) {
        const text = await response.text();
        loadError = `Failed to load artworks (${response.status}): ${text.slice(0, 120)}`;
        return;
      }
      const data = await response.json();
      artworks = data.artworks || [];
    } catch (err) {
      loadError = err?.message || 'Failed to load artworks.';
    } finally {
      loading = false;
    }
  };

  const openDeleteModal = (artwork) => {
    selectedArtwork = artwork;
    showDeleteModal = true;
  };

  const closeDeleteModal = () => {
    showDeleteModal = false;
    selectedArtwork = null;
  };

  const handleDeleteSuccess = () => {
    // Reload the artwork list
    showDeleteModal = false;
    selectedArtwork = null;
    fetchMyArtworks();
  };

  const handleRestoreSuccess = () => {
    // Reload the artwork list
    fetchMyArtworks();
  };

  onMount(async () => {
    await auth.init();
    const isArtist = $auth.user?.role === 'artist';
    const isAdmin = $auth.user?.role === 'admin';

    if (!$auth.isAuthenticated || (!isArtist && !isAdmin)) {
      loadError = 'You need an artist or admin account to view this page.';
      loading = false;
      return;
    }
    fetchMyArtworks();
  });
</script>

<div class="container">
  <h1>{$auth.user?.role === 'admin' ? 'All Artworks' : 'My Artworks'}</h1>
  {#if loadError}
    <div class="inline-error">{loadError}</div>
  {:else if loading}
    <div>Loading your artworks...</div>
  {:else}
    <div class="actions">
      <a href="/artworks/new" class="btn-primary">New Artwork</a>
    </div>
    {#if artworks.length === 0}
      <p>No artworks yet. Create your first artwork to start uploading photos.</p>
    {:else}
      <div class="artwork-grid">
        {#each artworks as artwork}
          <div class="card" class:soft-deleted={artwork.is_deleted}>
            <div class="card-header">
              <div class="title">{artwork.title || 'Untitled'}</div>
              <div class="meta"><code>{artwork.id}</code></div>
            </div>
            {#if artwork.is_deleted}
              <div class="deleted-indicator">
                <span class="deleted-badge">Scheduled for deletion</span>
                <span class="deleted-date">
                  {#if artwork.date_deleted}
                    {new Date(artwork.date_deleted).toLocaleDateString()}
                  {/if}
                </span>
              </div>
            {/if}
            <div class="card-body">
              {#if artwork.primary_photo?.thumbnail_url}
                <img src={`${PUBLIC_API_BASE_URL}${artwork.primary_photo.thumbnail_url}`} alt="Artwork thumbnail" />
              {/if}
              <div class="meta-row"><strong>Medium:</strong> {artwork.medium || 'N/A'}</div>
              <div class="meta-row"><strong>Storage:</strong> {artwork.storage?.location || 'N/A'}</div>
              <div class="meta-row"><strong>Photos:</strong> {artwork.photo_count || 0}</div>
            </div>
            <div class="card-actions">
              <a href={`/artworks/${artwork.id}`} class="btn-secondary">View</a>
              {#if !artwork.is_deleted}
                <a href={`/uploads?artwork_id=${artwork.id}`} class="btn-primary">Upload</a>
                <button on:click={() => openDeleteModal(artwork)} class="btn-danger">Delete</button>
              {:else}
                <div class="restore-wrapper">
                  <ArtworkRestoreButton
                    artworkId={artwork.id}
                    artworkTitle={artwork.title}
                    onSuccess={handleRestoreSuccess}
                  />
                </div>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<!-- Delete Modal -->
{#if showDeleteModal && selectedArtwork}
  <ArtworkDeleteModal
    artworkId={selectedArtwork.id}
    artworkTitle={selectedArtwork.title}
    onSuccess={handleDeleteSuccess}
    onCancel={closeDeleteModal}
  />
{/if}

<style>
  .container {
    max-width: 1100px;
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

  h1 {
    margin: 0 0 1.5rem 0;
    color: var(--text-primary);
  }

  .actions {
    margin: 1rem 0 1.5rem 0;
  }

  .artwork-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1.5rem;
  }

  .card {
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1rem;
    background: var(--bg-primary);
    transition: all 0.15s ease;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
    border-color: var(--accent-color);
  }

  .card.soft-deleted {
    border-color: #ffc107;
    background: rgba(255, 193, 7, 0.05);
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .title {
    font-weight: 600;
    font-size: 1.05rem;
  }

  .meta code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-family: monospace;
    font-weight: 600;
    font-size: 0.75rem;
  }

  .deleted-indicator {
    background: rgba(255, 193, 7, 0.1);
    border-left: 3px solid #ffc107;
    padding: 0.75rem;
    margin-bottom: 0.75rem;
    border-radius: 8px;
  }

  .deleted-badge {
    display: block;
    color: #ffc107;
    font-weight: 600;
    font-size: 0.875rem;
  }

  .deleted-date {
    display: block;
    color: var(--text-secondary);
    font-size: 0.75rem;
    margin-top: 0.25rem;
  }

  img {
    width: 100%;
    border-radius: 8px;
    object-fit: cover;
    max-height: 180px;
  }

  .meta-row {
    font-size: 0.9rem;
    margin-top: 0.35rem;
    color: var(--text-secondary);
  }

  .meta-row strong {
    color: var(--text-primary);
  }

  .card-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 1rem;
    flex-wrap: wrap;
  }

  .btn-primary,
  .btn-secondary,
  .btn-danger {
    display: inline-flex;
    align-items: center;
    padding: 0 16px;
    height: 36px;
    border-radius: 18px;
    text-decoration: none;
    border: none;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.15s ease;
  }

  .btn-primary {
    background: var(--accent-color);
    color: #fff;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .btn-primary:hover {
    filter: brightness(1.05);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
    transform: translateY(-1px);
  }

  .btn-secondary {
    border: 1px solid var(--border-color);
    color: var(--accent-color);
    background: transparent;
  }

  .btn-secondary:hover {
    background: rgba(0, 122, 255, 0.08);
    border-color: var(--accent-color);
  }

  .btn-danger {
    background: var(--error-color);
    color: #fff;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .btn-danger:hover {
    filter: brightness(1.1);
    box-shadow: 0 2px 8px rgba(211, 47, 47, 0.3);
    transform: translateY(-1px);
  }

  .restore-wrapper {
    width: 100%;
  }

  .inline-error {
    padding: 1rem 1.25rem;
    background: rgba(211, 47, 47, 0.08);
    color: var(--error-color);
    border: 1px solid rgba(211, 47, 47, 0.3);
    border-radius: 10px;
    margin: 1rem 0;
    font-weight: 500;
  }

  @media (max-width: 768px) {
    .container {
      padding: 1rem;
    }

    .artwork-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
