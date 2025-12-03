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
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks?owned=true&include_deleted=true&per_page=200`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      if (response.status === 401 || response.status === 403) {
        loadError = 'You need an artist account to view this page.';
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
    if (!$auth.isAuthenticated || $auth.user?.role !== 'artist') {
      loadError = 'You need an artist account to view this page.';
      loading = false;
      return;
    }
    fetchMyArtworks();
  });
</script>

<div class="container">
  <h1>My Artworks</h1>
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
  .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
  .actions { margin: 1rem 0; }
  .artwork-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 1rem; }
  .card { border: 1px solid var(--border-color); border-radius: 6px; padding: 0.75rem; background: var(--bg-secondary); transition: all 0.2s; }
  .card.soft-deleted { border-color: #ffc107; background: rgba(255, 193, 7, 0.05); }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
  .title { font-weight: 600; }
  .deleted-indicator {
    background: rgba(255, 193, 7, 0.1);
    border-left: 3px solid #ffc107;
    padding: 0.5rem;
    margin-bottom: 0.5rem;
    border-radius: 4px;
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
  img { width: 100%; border-radius: 4px; object-fit: cover; max-height: 180px; }
  .meta-row { font-size: 0.9rem; margin-top: 0.25rem; }
  .card-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap; }
  .btn-primary, .btn-secondary, .btn-danger { display: inline-block; padding: 0.4rem 0.75rem; border-radius: 4px; text-decoration: none; border: none; cursor: pointer; font-size: 0.875rem; transition: background 0.2s; }
  .btn-primary { background: var(--accent-color); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-secondary { border: 1px solid var(--border-color); color: var(--text-primary); background: transparent; }
  .btn-secondary:hover { background: var(--bg-tertiary); }
  .btn-danger { background: var(--error-color); color: #fff; }
  .btn-danger:hover { background: #b71c1c; }
  .restore-wrapper { width: 100%; }
  .inline-error { color: #b91c1c; margin: 0.75rem 0; }
</style>
