<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';

  export let data;

  // Helper to get full thumbnail URL
  const getThumbnailUrl = (thumbnail) => {
    if (!thumbnail) return null;
    if (thumbnail.startsWith('http')) return thumbnail;
    return `${PUBLIC_API_BASE_URL}${thumbnail}`;
  };

  // Pagination helper
  const getPaginationUrl = (page) => {
    const params = new URLSearchParams();
    params.set('page', page.toString());
    if (data.filters.search) params.set('search', data.filters.search);
    if (data.filters.artistId) params.set('artist_id', data.filters.artistId);
    if (data.filters.medium) params.set('medium', data.filters.medium);
    if (data.filters.storageId) params.set('storage_id', data.filters.storageId);
    if (data.filters.ordering) params.set('ordering', data.filters.ordering);
    return `/artworks?${params.toString()}`;
  };

  const handleSelectChange = (event) => {
    event.currentTarget.form?.submit();
  };
</script>

<div class="container">
  <header>
    <h1>Artworks</h1>
    {#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
      <a href="/artworks/new" class="btn-primary">Add New Artwork</a>
    {/if}
  </header>

  <form method="GET" class="filters">
    <div class="filter-group">
      <label for="search">Search</label>
      <input
        id="search"
        name="search"
        type="search"
        value={data.filters.search}
        placeholder="Search by title, artist, or medium..."
        autocomplete="off"
      />
    </div>

    <div class="filter-group">
      <label for="ordering">Order</label>
      <select id="ordering" name="ordering" on:change={handleSelectChange}>
        <option value="title_asc" selected={data.filters.ordering === 'title_asc'}>
          A-Z
        </option>
        <option value="title_desc" selected={data.filters.ordering === 'title_desc'}>
          Z-A
        </option>
      </select>
    </div>

    <div class="filter-group">
      <label for="artist_id">Artist</label>
      <select id="artist_id" name="artist_id" on:change={handleSelectChange}>
        <option value="" selected={!data.filters.artistId}>
          All artists
        </option>
        {#each data.artists as artist}
          <option
            value={artist.id}
            selected={data.filters.artistId === artist.id}
          >
            {artist.name} ({artist.id})
          </option>
        {/each}
      </select>
      {#if data.artistsError}
        <p class="filter-hint">Unable to load artists: {data.artistsError}</p>
      {/if}
    </div>

    <div class="filter-group">
      <label for="storage_id">Location</label>
      <select id="storage_id" name="storage_id" on:change={handleSelectChange}>
        <option value="" selected={!data.filters.storageId}>
          All locations
        </option>
        {#each data.storage as location}
          <option
            value={location.id}
            selected={data.filters.storageId === location.id}
          >
            {location.location} ({location.id})
          </option>
        {/each}
      </select>
      {#if data.storageError}
        <p class="filter-hint">Unable to load locations: {data.storageError}</p>
      {/if}
    </div>

    <div class="filter-group">
      <label for="medium">Medium</label>
      <input
        id="medium"
        name="medium"
        type="text"
        value={data.filters.medium}
        placeholder="e.g. Oil, Watercolor"
      />
    </div>

    <button type="submit" class="btn-primary">Filter</button>
    <a href="/artworks" class="btn-secondary">Clear</a>
  </form>

  {#if data.error}
    <div class="error">{data.error}</div>
  {:else if data.artworks.length === 0}
    <p class="no-results">No artworks found.</p>
  {:else}
    <div class="artwork-grid">
      {#each data.artworks as artwork}
        <a href="/artworks/{artwork.id}" class="artwork-card">
          <div class="artwork-thumbnail">
            {#if artwork.primary_photo?.thumbnail_url}
              <img
                src={getThumbnailUrl(artwork.primary_photo.thumbnail_url)}
                alt={artwork.title}
              />
            {:else}
              <div class="no-image">No Image</div>
            {/if}
          </div>

          <div class="artwork-info">
            <h3>{artwork.title}</h3>
            <p class="artwork-id">
              <code>{artwork.id}</code>
            </p>
            <p class="artist-name">
              {artwork.artist?.name || 'Unknown Artist'}
            </p>
            {#if artwork.medium}
              <p class="medium">{artwork.medium}</p>
            {/if}
            {#if artwork.storage?.location}
              <p class="storage">
                Storage: {artwork.storage.location}
              </p>
            {/if}
          </div>
        </a>
      {/each}
    </div>

    {#if data.pagination}
      <div class="pagination">
        <div class="pagination-info">
          Showing {data.pagination.total > 0 ? ((data.pagination.page - 1) * data.pagination.per_page) + 1 : 0}–{Math.min(data.pagination.page * data.pagination.per_page, data.pagination.total)} of {data.pagination.total}
        </div>

        <div class="pagination-controls">
          {#if data.pagination.has_prev}
            <a href={getPaginationUrl(data.pagination.page - 1)} class="btn-secondary">Previous</a>
          {:else}
            <button class="btn-secondary" disabled>Previous</button>
          {/if}

          <span class="page-number">Page {data.pagination.page} of {data.pagination.total_pages}</span>

          {#if data.pagination.has_next}
            <a href={getPaginationUrl(data.pagination.page + 1)} class="btn-secondary">Next</a>
          {:else}
            <button class="btn-secondary" disabled>Next</button>
          {/if}
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  h1 {
    margin: 0;
    color: var(--text-primary);
  }

  .filters {
    display: flex;
    gap: 1rem;
    margin-bottom: 2rem;
    padding: 1.5rem;
    background: var(--bg-tertiary);
    border-radius: 8px;
    flex-wrap: wrap;
    align-items: flex-end;
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    flex: 1;
    min-width: 200px;
  }

  .filter-group label {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .filter-group input,
  .filter-group select {
    padding: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
  }

  .filter-group input:focus,
  .filter-group select:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .filter-hint {
    margin: 0;
    font-size: 0.75rem;
    color: var(--danger-color);
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

  .btn-secondary:disabled {
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

  .no-results {
    text-align: center;
    color: var(--text-secondary);
    padding: 3rem;
  }

  .artwork-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 350px));
    gap: 1.5rem;
    margin-bottom: 2rem;
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

  .artist-name {
    color: var(--accent-color);
    font-weight: 500;
    margin: 0 0 0.25rem 0;
  }

  .medium {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0 0 0.25rem 0;
  }

  .storage {
    color: var(--text-tertiary);
    font-size: 0.75rem;
    margin: 0;
  }

  .pagination {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    background: var(--bg-tertiary);
    border-radius: 8px;
  }

  .pagination-info {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .pagination-controls {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .page-number {
    color: var(--text-primary);
    font-size: 0.875rem;
  }

  @media (max-width: 768px) {
    .filters {
      flex-direction: column;
      align-items: stretch;
    }

    .filter-group {
      min-width: 100%;
    }

    .pagination {
      flex-direction: column;
      gap: 1rem;
    }

    .artwork-grid {
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    }
  }
</style>
