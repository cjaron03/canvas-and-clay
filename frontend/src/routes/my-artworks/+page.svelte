<script>
  import { onMount } from 'svelte';
  import { auth } from '$lib/stores/auth';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  let artworks = [];
  let loading = true;
  let loadError = '';

  const fetchMyArtworks = async () => {
    loading = true;
    loadError = '';
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks?owned=true&per_page=200`, {
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
          <div class="card">
            <div class="card-header">
              <div class="title">{artwork.title || 'Untitled'}</div>
              <div class="meta"><code>{artwork.id}</code></div>
            </div>
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
              <a href={`/uploads?artwork_id=${artwork.id}`} class="btn-primary">Upload</a>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
  .actions { margin: 1rem 0; }
  .artwork-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 1rem; }
  .card { border: 1px solid var(--border-color); border-radius: 6px; padding: 0.75rem; background: var(--bg-secondary); }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
  .title { font-weight: 600; }
  img { width: 100%; border-radius: 4px; object-fit: cover; max-height: 180px; }
  .meta-row { font-size: 0.9rem; margin-top: 0.25rem; }
  .card-actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
  .btn-primary, .btn-secondary { display: inline-block; padding: 0.4rem 0.75rem; border-radius: 4px; text-decoration: none; }
  .btn-primary { background: var(--accent-color); color: #fff; }
  .btn-secondary { border: 1px solid var(--border-color); color: var(--text-primary); }
  .inline-error { color: #b91c1c; margin: 0.75rem 0; }
</style>
