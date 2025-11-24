<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  export let data;

  const getThumbnailUrl = (thumbnail) => {
    if (!thumbnail) return null;
    if (thumbnail.startsWith('http')) return thumbnail;
    return `${PUBLIC_API_BASE_URL}${thumbnail}`;
  };

  const getPaginationUrl = (page) => {
    const params = new URLSearchParams();
    params.set('page', page.toString());
    // TODO include per page? 
    // TODO include owned_only ?
    if (data.filters.search) params.set('search', data.filters.search);
    if (data.filters.medium) params.set('medium', data.filters.medium);
    if (data.filters.storageId) params.set('storage_id', data.filters.storageId);
    if (data.filters.ordering) params.set('ordering', data.filters.ordering);
    return `/artists?${params.toString()}`;
  };

  const handleSelectChange = (event) => {
    event.currentTarget.form?.submit();
  };
</script>

<div class="container">
  <header>
    <h1>Artists</h1>
  </header>

  <form method="GET" class="filters">
    <div class="filter-group">
      <label for="search">Search</label>
      <input
        id="search"
        name="search"
        type="search"
        value={data.filters.search}
        placeholder="Search by name, ID, medium, bio, or location..."
        autocomplete="off"
      />
    </div>

    <div class="filter-group">
      <label for="ordering">Order</label>
      <select id="ordering" name="ordering" on:change={handleSelectChange}>
        <option value="name_asc" selected={data.filters.ordering === 'name_asc'}>
          A-Z
        </option>
        <option value="name_desc" selected={data.filters.ordering === 'name_desc'}>
          Z-A
        </option>
      </select>
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
    <a href="/artists" class="btn-secondary">Clear</a>
  </form>

  {#if data.error}
    <div class="error">{data.error}</div>
  {:else if data.artists.length === 0}
    <p class="no-results">No artists found.</p>
  {:else}
    <div class="artist-grid">
      {#each data.artists as artist}
        <a href="/artists/{artist.id}" class="artist-card">
          <div class="artist-thumbnail">
            {#if artist.primary_photo?.thumbnail_url}
              <img
                src={getThumbnailUrl(artist.primary_photo.thumbnail_url)}
                alt={`${artist.first_name} ${artist.last_name}`}
              />
            {:else}
              <div class="no-image">No Image</div>
            {/if}
          </div>

          <div class="artist-info">
            <h3>{artist.first_name} {artist.last_name}</h3>
            <p class="artist-id">
              <code>{artist.id}</code>
            </p>
            {#if artist.artist?.email}
              <p class="artist-email">{artist.artist.email}</p>
            {/if}
            {#if artist.date_created}
              <p class="artist-created">
                First recorded artwork: {artist.date_created}
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

  .artist-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 350px));
    gap: 1.5rem;
    margin-bottom: 2rem;
    justify-content: center;
  }

  .artist-card {
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

  .artist-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
  }

  .artist-thumbnail {
    width: 100%;
    height: 200px;
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  .artist-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .no-image {
    color: var(--text-tertiary);
    font-size: 0.875rem;
  }

  .artist-info {
    padding: 1rem;
  }

  .artist-info h3 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.1rem;
  }

  .artist-id {
    margin: 0 0 0.5rem 0;
    font-size: 0.75rem;
  }

  .artist-id code {
    background: var(--bg-secondary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
  }

  .artist-email {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0 0 0.25rem 0;
  }

  .artist-created {
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

    .artist-grid {
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    }
  }
</style>
