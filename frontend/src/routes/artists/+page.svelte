<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount, onDestroy } from 'svelte';

  export let data;

  let suggestions = [];
  let showSuggestions = false;
  let searchContainer;
  let debounceTimer;

  // Reactive filter state initialized from URL data
  let filters = {
    search: data.filters.search || '',
    storageId: data.filters.storageId || '',
    ordering: data.filters.ordering || 'name_asc'
  };

  // Update filters when URL changes
  $: {
    filters.search = $page.url.searchParams.get('search') || '';
    filters.storageId = $page.url.searchParams.get('storage_id') || '';
    filters.ordering = $page.url.searchParams.get('ordering') || 'name_asc';
  }

  // Takes the artist photo url and generates a thumbnail URL for it
  const getThumbnailUrl = (artist_photo_url) => {
    if (!artist_photo_url) return null;
    if (artist_photo_url.startsWith('http')) return artist_photo_url;
    return `${PUBLIC_API_BASE_URL}${artist_photo_url}`;
  };

  // Helpers to calculate page ranges based on /artists GET pagination results
  $: pageStart = data.pagination.total_filtered_artists > 0
    ? (data.pagination.page - 1) * data.pagination.per_page + 1
    : 0;

  $: pageEnd = Math.min(
    data.pagination.page * data.pagination.per_page,
    data.pagination.total_filtered_artists
  );

  const updateFilters = (newFilters = {}, resetPage = true) => {
    const params = new URLSearchParams($page.url.searchParams);
    
    const nextState = { ...filters, ...newFilters };
    
    if (nextState.search) params.set('search', nextState.search); else params.delete('search');
    if (nextState.storageId) params.set('storage_id', nextState.storageId); else params.delete('storage_id');
    if (nextState.ordering) params.set('ordering', nextState.ordering);
    
    if (resetPage) params.set('page', '1');

    goto(`?${params.toString()}`, { keepFocus: true, noScroll: true });
  };

  const fetchSuggestions = async (query) => {
    if (query.length < 2) {
      suggestions = [];
      showSuggestions = false;
      return;
    }
    try {
      // Re-use the artwork/artist suggest endpoint
      const res = await fetch(`${PUBLIC_API_BASE_URL}/api/artworks/suggest?q=${encodeURIComponent(query)}`);
      if (res.ok) {
        // Filter only artists from the suggestion list
        const allSuggestions = await res.json();
        suggestions = allSuggestions.filter(s => s.type === 'artist');
        showSuggestions = suggestions.length > 0;
      }
    } catch (err) {
      console.error('Failed to fetch suggestions:', err);
    }
  };

  const handleSearchInput = (e) => {
    filters.search = e.target.value;
    clearTimeout(debounceTimer);
    
    if (filters.search.length >= 2) {
      debounceTimer = setTimeout(() => {
        fetchSuggestions(filters.search);
        updateFilters({ search: filters.search });
      }, 300);
    } else {
      suggestions = [];
      showSuggestions = false;
      debounceTimer = setTimeout(() => {
        updateFilters({ search: filters.search });
      }, 300);
    }
  };

  const selectSuggestion = (suggestion) => {
    goto(`/artists/${suggestion.id}`);
    showSuggestions = false;
    filters.search = '';
  };

  const handleClickOutside = (event) => {
    if (searchContainer && !searchContainer.contains(event.target)) {
      showSuggestions = false;
    }
  };

  const clearFilters = () => {
    filters = {
      search: '',
      storageId: '',
      ordering: 'name_asc'
    };
    goto('/artists', { noScroll: true });
  };

  const getPaginationUrl = (pageNumber) => {
    const params = new URLSearchParams();
    params.set('page', pageNumber.toString());
    if (filters.search) params.set('search', filters.search);
    if (filters.storageId) params.set('storage_id', filters.storageId);
    if (filters.ordering) params.set('ordering', filters.ordering);
    return `/artists?${params.toString()}`;
  };

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
  });
  
  onDestroy(() => {
    if (typeof document !== 'undefined') {
      document.removeEventListener('click', handleClickOutside);
    }
  });
</script>

<div class="container">
  <header>
    <h1>Artists</h1>
    {#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
      <a href="/artists/new" class="btn-primary">Add a new artist</a>
    {/if}
  </header>

  <div class="filters-container">
    <div class="search-bar" bind:this={searchContainer}>
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="search-icon"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input
        type="text"
        placeholder="Search by name, ID, medium, bio, or location..."
        value={filters.search}
        on:input={handleSearchInput}
        on:focus={() => { if (filters.search.length >= 2) showSuggestions = true; }}
        aria-label="Search artists"
      />
      {#if showSuggestions && suggestions.length > 0}
        <div class="suggestions-dropdown">
          {#each suggestions as suggestion}
            <button class="suggestion-item" on:click={() => selectSuggestion(suggestion)}>
              <div class="suggestion-icon">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
              </div>
              <div class="suggestion-content">
                <div class="suggestion-text">{suggestion.text}</div>
                <div class="suggestion-subtext">Artist</div>
              </div>
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="filter-controls">
      <div class="select-wrapper">
        <select 
          value={filters.ordering} 
          on:change={(e) => updateFilters({ ordering: e.target.value })}
          aria-label="Sort order"
        >
          <option value="name_asc">Name (A-Z)</option>
          <option value="name_desc">Name (Z-A)</option>
        </select>
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="chevron"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </div>

      <div class="select-wrapper">
        <select 
          value={filters.storageId} 
          on:change={(e) => updateFilters({ storageId: e.target.value })}
          aria-label="Filter by location"
        >
          <option value="">All Locations</option>
          {#each data.storage as location}
            <option value={location.id}>{location.location}</option>
          {/each}
        </select>
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="chevron"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </div>

      <button class="btn-reset" on:click={clearFilters} aria-label="Clear filters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        Reset
      </button>
    </div>
  </div>

  <!-- Render artist grid -->
  {#if data.error}
    <div class="error">{data.error}</div>
  {:else if data.artists.length === 0}
    <p class="no-results">No artists found.</p>
  {:else}
    <div class="artist-grid">
      {#each data.artists as artist}
        <a href="/artists/{artist.id}" class="artist-card">
          <div class="artist-thumbnail">
            {#if artist.photo}
              <img
                src={getThumbnailUrl(artist.photo)}
                alt={`${artist.first_name} ${artist.last_name}`}
              />
            {:else}
              <div class="no-image-placeholder">
                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                <span>No Photo</span>
              </div>
            {/if}
          </div>

          <div class="artist-info">
            <h3>{artist.first_name} {artist.last_name}</h3>
            <p class="artist-id">
              <code>{artist.id}</code>
            </p>
            {#if artist.email}
              <p class="artist-email">{artist.email}</p>
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

    <!-- Renders pagination at the bottom of the page -->
    {#if data.pagination}
      <div class="pagination">
        <div class="pagination-info">
          {#if data.pagination.total_pages <= 1}
            Showing {data.pagination.total_filtered_artists} result{data.pagination.total_filtered_artists === 1 ? '' : 's'}
          {:else}
            Showing {pageStart}–{pageEnd} of {data.pagination.total_filtered_artists} results
          {/if}
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

  /* Modern Filters Layout */
  .filters-container {
    background: var(--bg-tertiary);
    padding: 1.25rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    border: 1px solid var(--border-color);
  }

  .search-bar {
    position: relative;
    width: 100%;
    display: grid;
    grid-template-columns: 40px 1fr;
    align-items: center;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    background: var(--bg-secondary);
    transition: all 0.2s;
  }

  .search-bar:focus-within {
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(90, 159, 212, 0.1);
  }

  .search-icon {
    justify-self: center;
    color: var(--text-secondary);
    pointer-events: none;
  }

  .search-bar input {
    width: 100%;
    padding: 0.75rem 1rem 0.75rem 0;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 0.95rem;
  }

  .search-bar input:focus {
    outline: none;
    box-shadow: none;
  }

  .suggestions-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-top: none;
    border-radius: 0 0 6px 6px;
    z-index: 100;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    max-height: 300px;
    overflow-y: auto;
  }

  .suggestion-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    padding: 0.75rem 1rem;
    border: none;
    background: transparent;
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
    transition: background 0.15s;
    border-bottom: 1px solid var(--border-color);
  }

  .suggestion-item:last-child {
    border-bottom: none;
  }

  .suggestion-item:hover {
    background: var(--bg-tertiary);
  }

  .suggestion-icon {
    color: var(--text-secondary);
    display: flex;
    align-items: center;
  }

  .suggestion-content {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .suggestion-text {
    font-weight: 500;
    font-size: 0.9rem;
  }

  .suggestion-subtext {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  .filter-controls {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    align-items: center;
  }

  .select-wrapper {
    position: relative;
  }

  .select-wrapper select {
    width: 100%;
    padding: 0.75rem 2.5rem 0.75rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: 0.95rem;
    appearance: none;
    cursor: pointer;
    transition: border-color 0.2s;
  }

  .select-wrapper select:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .chevron {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-secondary);
    pointer-events: none;
  }

  .btn-reset {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    font-weight: 500;
  }

  .btn-reset:hover {
    background: var(--bg-secondary);
    color: var(--error-color);
    border-color: var(--error-color);
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
    border: 1px solid var(--border-color);
  }

  .artist-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
    border-color: var(--accent-color);
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

  .no-image-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    height: 100%;
    background: var(--bg-secondary);
    color: var(--text-tertiary);
    font-size: 0.875rem;
    text-align: center;
    gap: 0.5rem;
  }

  .no-image-placeholder svg {
    color: var(--text-tertiary);
    opacity: 0.7;
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
    .filters-container {
      padding: 1rem;
    }
    
    .filter-controls {
      grid-template-columns: 1fr;
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
