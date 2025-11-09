 <!-- form taht implements server-side rendering -->

<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';

  // data is exported from load() in` routes/search/+page.server.js
  export let data;

  // Autocomplete state
  let searchQuery = data.q || '';
  let autocompleteSuggestions = [];
  let showAutocomplete = false;
  let selectedIndex = -1;
  let isLoadingSuggestions = false;
  let searchInputElement;
  let autocompleteTimeout;

  // helper to figure out the correct link for each result before rendering it
  const resolveHref = (entity, fallbackPrefix) => {
    if (!entity) return null;

    if (typeof entity === 'string') {
      return entity.startsWith('http') || entity.startsWith('/') ? entity : null;
    }

    // For photos, don't use the url field (it's an external backend URL)
    // Use profile_url or id-based route instead
    if (entity.type === 'photo') {
      if (entity.profile_url) return entity.profile_url;
      if (entity.id) return `${fallbackPrefix}/${entity.id}`;
      return null;
    }

    if (entity.profile_url) return entity.profile_url;
    // Only use url field for non-photo entities, and only if it's a relative path
    if (entity.url && entity.url.startsWith('/')) return entity.url;
    if (entity.id) return `${fallbackPrefix}/${entity.id}`;

    return null;
  };

  const getArtworkHref = (item) => resolveHref(item, '/artworks');
  const getArtistHref = (item) => resolveHref(item, '/artists');
  const getLocationHref = (item) => resolveHref(item, '/locations');

  // Helper to get full thumbnail URL
  const getThumbnailUrl = (thumbnail) => {
    if (!thumbnail) return null;
    // If thumbnail is already a full URL, return as-is
    if (thumbnail.startsWith('http')) return thumbnail;
    // Otherwise prepend API base URL
    return `${PUBLIC_API_BASE_URL}${thumbnail}`;
  };

  // Helper to get full photo URL
  const getPhotoUrl = (url) => {
    if (!url) return null;
    // If URL is already a full URL, return as-is
    if (url.startsWith('http')) return url;
    // If PUBLIC_API_BASE_URL is not available (e.g., during SSR), return null to prevent relative URLs
    if (!PUBLIC_API_BASE_URL || typeof PUBLIC_API_BASE_URL !== 'string') return null;
    // Ensure we have a leading slash
    const path = url.startsWith('/') ? url : `/${url}`;
    // Prepend API base URL to make it absolute
    const fullUrl = `${PUBLIC_API_BASE_URL}${path}`;
    // Double-check it's absolute before returning
    return fullUrl.startsWith('http') ? fullUrl : null;
  };

  // Fetch autocomplete suggestions
  const fetchSuggestions = async (query) => {
    if (!query.trim() || query.length < 2) {
      autocompleteSuggestions = [];
      showAutocomplete = false;
      return;
    }

    isLoadingSuggestions = true;
    try {
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/search?q=${encodeURIComponent(query)}`,
        {
          headers: { accept: 'application/json' }
        }
      );

      if (response.ok) {
        const data = await response.json();
        autocompleteSuggestions = (data.items || []).slice(0, 8); // Limit to 8 suggestions
        showAutocomplete = autocompleteSuggestions.length > 0;
        selectedIndex = -1;
      } else {
        autocompleteSuggestions = [];
        showAutocomplete = false;
      }
    } catch (error) {
      console.error('Failed to fetch suggestions:', error);
      autocompleteSuggestions = [];
      showAutocomplete = false;
    } finally {
      isLoadingSuggestions = false;
    }
  };

  // Debounced search function
  const handleInput = (e) => {
    const value = e.target.value;
    searchQuery = value;

    // Clear existing timeout
    if (autocompleteTimeout) {
      clearTimeout(autocompleteTimeout);
    }

    // Debounce: wait 300ms before fetching suggestions
    autocompleteTimeout = setTimeout(() => {
      fetchSuggestions(value);
    }, 300);
  };

  // Handle keyboard navigation
  const handleKeyDown = (e) => {
    if (!showAutocomplete || autocompleteSuggestions.length === 0) {
      if (e.key === 'Enter') {
        // Submit form if no suggestions
        return;
      }
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, autocompleteSuggestions.length - 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, -1);
    } else if (e.key === 'Enter' && selectedIndex >= 0) {
      e.preventDefault();
      selectSuggestion(autocompleteSuggestions[selectedIndex]);
    } else if (e.key === 'Escape') {
      showAutocomplete = false;
      selectedIndex = -1;
    }
  };

  // Select a suggestion
  const selectSuggestion = (item) => {
    // Handle photos specially
    if (item.type === 'photo') {
      // If photo is associated with an artwork, navigate to the artwork
      if (item.artwork) {
        const artworkHref = item.artwork.profile_url || `/artworks/${item.artwork.id}`;
        if (artworkHref.startsWith('/')) {
          goto(artworkHref);
        } else if (artworkHref.startsWith('http')) {
          window.open(artworkHref, '_blank', 'noopener,noreferrer');
        }
      } else if (item.url) {
        // Orphaned photo - open full-size image in new tab
        const photoUrl = getPhotoUrl(item.url);
        if (photoUrl && photoUrl.startsWith('http')) {
          window.open(photoUrl, '_blank', 'noopener,noreferrer');
        }
      } else {
        // Fallback: perform search
        const searchTerm = item.filename || item.id || searchQuery;
        goto(`/search?q=${encodeURIComponent(searchTerm)}`);
      }
      showAutocomplete = false;
      selectedIndex = -1;
      return;
    }
    
    // For internal routes (artworks, artists, locations)
    const href = getArtworkHref(item) || getArtistHref(item) || getLocationHref(item);
    if (href) {
      // Only use goto for internal routes (starting with /)
      if (href.startsWith('/')) {
        goto(href);
      } else if (href.startsWith('http')) {
        // External URL - open in new tab
        window.open(href, '_blank', 'noopener,noreferrer');
      }
    } else {
      // If no direct link, perform search with the item's title/name
      const searchTerm = item.title || item.name || item.filename || searchQuery;
      goto(`/search?q=${encodeURIComponent(searchTerm)}`);
    }
    showAutocomplete = false;
    selectedIndex = -1;
  };

  // Format suggestion text
  const getSuggestionText = (item) => {
    if (item.type === 'artwork') {
      return item.title || item.id;
    } else if (item.type === 'artist') {
      return item.name || item.full_name || 'Artist';
    } else if (item.type === 'location') {
      return item.name || 'Location';
    } else if (item.type === 'photo') {
      return item.filename || item.id;
    }
    return '';
  };

  // Get suggestion type label
  const getSuggestionType = (item) => {
    return item.type ? item.type.charAt(0).toUpperCase() + item.type.slice(1) : '';
  };

  // Handle form submission
  const handleSubmit = (e) => {
    if (selectedIndex >= 0 && autocompleteSuggestions[selectedIndex]) {
      e.preventDefault();
      selectSuggestion(autocompleteSuggestions[selectedIndex]);
    }
    // Otherwise, let form submit normally
  };

  // Close autocomplete when clicking outside
  const handleClickOutside = (e) => {
    if (searchInputElement && !searchInputElement.contains(e.target)) {
      showAutocomplete = false;
    }
  };

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
    return () => {
      document.removeEventListener('click', handleClickOutside);
      if (autocompleteTimeout) {
        clearTimeout(autocompleteTimeout);
      }
    };
  });
</script>

<div class="search-container">
  <h1>Search</h1>
  
  <form method="GET" role="search" class="search-form" on:submit={handleSubmit}>
    <div class="search-input-wrapper" bind:this={searchInputElement}>
      <label for="q" class="sr-only">Search</label>
      <input
        id="q"
        name="q"
        type="search"
        bind:value={searchQuery}
        on:input={handleInput}
        on:keydown={handleKeyDown}
        on:focus={() => {
          if (autocompleteSuggestions.length > 0) {
            showAutocomplete = true;
          }
        }}
        placeholder="Search artworks, artists, locations, photos…"
        autocomplete="off"
        class="search-input"
      />
      <button type="submit" class="search-button">Search</button>
      
      {#if showAutocomplete && autocompleteSuggestions.length > 0}
        <div class="autocomplete-dropdown">
          {#each autocompleteSuggestions as suggestion, index}
            <button
              type="button"
              class="autocomplete-item"
              class:selected={index === selectedIndex}
              on:click={() => selectSuggestion(suggestion)}
              on:mouseenter={() => selectedIndex = index}
            >
              {#if suggestion.thumbnail}
                <div class="suggestion-thumbnail">
                  <img src={getThumbnailUrl(suggestion.thumbnail)} alt="" />
                </div>
              {:else}
                <div class="suggestion-icon">
                  {#if suggestion.type === 'artwork'}
                    Artwork
                  {:else if suggestion.type === 'artist'}
                    Artist
                  {:else if suggestion.type === 'location'}
                    Location
                  {:else if suggestion.type === 'photo'}
                    Photo
                  {/if}
                </div>
              {/if}
              <div class="suggestion-content">
                <div class="suggestion-title">{getSuggestionText(suggestion)}</div>
                {#if suggestion.type === 'artwork' && suggestion.artist}
                  <div class="suggestion-meta">
                    {typeof suggestion.artist === 'string' ? suggestion.artist : suggestion.artist.name}
                  </div>
                {:else if suggestion.type === 'photo' && suggestion.artwork}
                  <div class="suggestion-meta">
                    {suggestion.artwork.title || suggestion.artwork.id}
                  </div>
                {/if}
              </div>
              <div class="suggestion-type" class:artwork-type={suggestion.type === 'artwork'} class:photo-type={suggestion.type === 'photo'}>{getSuggestionType(suggestion)}</div>
            </button>
          {/each}
        </div>
      {/if}
      
      {#if isLoadingSuggestions}
        <div class="autocomplete-loading">Searching...</div>
      {/if}
    </div>
  </form>

  {#if data.error}
    <div class="error-message">
      <p><strong>Error:</strong> {data.error}</p>
    </div>
  {:else if data.results?.length}
    <div class="results-header">
      <h2>Search Results</h2>
      <p class="results-count">{data.results.length} result{data.results.length !== 1 ? 's' : ''} found</p>
    </div>
    <div class="results-grid">
      {#each data.results as item}
        {#if item?.type === 'artwork'}
          <div class="result-card artwork-card">
            {#if item?.thumbnail}
              <div class="result-thumbnail">
                <a href={getArtworkHref(item)}>
                  <img src={getThumbnailUrl(item.thumbnail)} alt={`Thumbnail for ${item.title ?? 'artwork'}`} />
                </a>
              </div>
            {:else}
              <div class="result-thumbnail no-image">
                <div>No Image</div>
              </div>
            {/if}
            <div class="result-content">
              <div class="result-type-badge artwork-badge">Artwork</div>
              {#if item?.title}
                <h3 class="result-title">
                  {#if getArtworkHref(item)}
                    <a href={getArtworkHref(item)}>{item.title}</a>
                  {:else}
                    <span>{item.title}</span>
                  {/if}
                </h3>
              {/if}
              {#if item?.id}
                <p class="result-id">ID: <code>{item.id}</code></p>
              {/if}
              {#if item?.artist}
                <p class="result-meta">
                  <span class="meta-label">Artist:</span>
                  {#if item.artist_profile_url || getArtistHref(item.artist)}
                    <a href={item.artist_profile_url ?? getArtistHref(item.artist)} class="meta-link">
                      {typeof item.artist === 'string' ? item.artist : item.artist?.name}
                    </a>
                  {:else}
                    <span>{typeof item.artist === 'string' ? item.artist : item.artist?.name}</span>
                  {/if}
                </p>
              {:else if item?.artist_name}
                <p class="result-meta">
                  <span class="meta-label">Artist:</span>
                  <span>{item.artist_name}</span>
                </p>
              {/if}
              {#if item?.location}
                <p class="result-meta">
                  <span class="meta-label">Location:</span>
                  {#if typeof item.location === 'string'}
                    <span>{item.location}</span>
                  {:else}
                    {#if item.location.profile_url || getLocationHref(item.location)}
                      <a href={item.location.profile_url ?? getLocationHref(item.location)} class="meta-link">
                        {item.location?.name}
                      </a>
                    {:else}
                      <span>{item.location?.name}</span>
                    {/if}
                  {/if}
                </p>
              {/if}
            </div>
          </div>
        {:else if item?.type === 'artist'}
          <div class="result-card artist-card">
            <div class="result-content">
              <div class="result-type-badge">Artist</div>
              <h3 class="result-title">
                {#if item?.name}
                  {#if getArtistHref(item)}
                    <a href={getArtistHref(item)}>{item.name}</a>
                  {:else}
                    <span>{item.name}</span>
                  {/if}
                {:else if item?.full_name}
                  {#if getArtistHref(item)}
                    <a href={getArtistHref(item)}>{item.full_name}</a>
                  {:else}
                    <span>{item.full_name}</span>
                  {/if}
                {:else}
                  {#if getArtistHref(item)}
                    <a href={getArtistHref(item)}>{item?.artist ?? 'View profile'}</a>
                  {:else}
                    <span>{item?.artist ?? 'Artist'}</span>
                  {/if}
                {/if}
              </h3>
            </div>
          </div>
        {:else if item?.type === 'location'}
          <div class="result-card location-card">
            <div class="result-content">
              <div class="result-type-badge">Location</div>
              <h3 class="result-title">
                {#if item?.name}
                  {#if getLocationHref(item)}
                    <a href={getLocationHref(item)}>{item.name}</a>
                  {:else}
                    <span>{item.name}</span>
                  {/if}
                {:else}
                  {#if getLocationHref(item)}
                    <a href={getLocationHref(item)}>{item?.location ?? 'View location'}</a>
                  {:else}
                    <span>{item?.location ?? 'Location'}</span>
                  {/if}
                {/if}
              </h3>
            </div>
          </div>
        {:else if item?.type === 'photo'}
          <div class="result-card photo-card">
            {#if item?.thumbnail}
              {@const photoUrl = item.url ? getPhotoUrl(item.url) : null}
              <div class="result-thumbnail">
                {#if photoUrl && photoUrl.startsWith('http')}
                  <a 
                    href={photoUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    data-sveltekit-preload-data="off"
                    data-sveltekit-noscroll
                  >
                    <img src={getThumbnailUrl(item.thumbnail)} alt={`Photo: ${item.filename ?? 'image'}`} />
                  </a>
                {:else}
                  <div>
                    <img src={getThumbnailUrl(item.thumbnail)} alt={`Photo: ${item.filename ?? 'image'}`} />
                  </div>
                {/if}
              </div>
            {:else}
              <div class="result-thumbnail no-image">
                <div>No Image</div>
              </div>
            {/if}
            <div class="result-content">
              <div class="result-type-badge photo-badge">Photo</div>
              <h3 class="result-title">{item.filename}</h3>
              {#if item?.id}
                <p class="result-id">Photo ID: <code>{item.id}</code></p>
              {/if}
              {#if item?.artwork}
                <p class="result-meta">
                  <span class="meta-label">Artwork:</span>
                  {#if item.artwork.profile_url}
                    <a href={item.artwork.profile_url} class="meta-link">{item.artwork.title ?? item.artwork.id}</a>
                  {:else}
                    <span>{item.artwork.title ?? item.artwork.id}</span>
                  {/if}
                </p>
              {:else if item?.orphaned}
                <span class="orphaned-badge">Not associated with artwork</span>
              {/if}
              {#if item?.width && item?.height}
                <p class="result-meta">
                  <span class="meta-label">Dimensions:</span>
                  <span>{item.width} × {item.height} pixels</span>
                </p>
              {/if}
            </div>
          </div>
        {:else}
          <div class="result-card">
            <div class="result-content">
              <pre>{JSON.stringify(item, null, 2)}</pre>
            </div>
          </div>
        {/if}
      {/each}
    </div>
  {:else if data.q?.trim()}
    <div class="no-results">
      <p>No results found for "<strong>{data.q}</strong>"</p>
      <p class="no-results-hint">Try different keywords or check your spelling.</p>
    </div>
  {/if}
</div>

<style>
  .search-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  h1 {
    color: var(--text-primary);
    margin-bottom: 2rem;
    font-size: 2.5rem;
    font-weight: 700;
  }

  .search-form {
    margin-bottom: 3rem;
  }

  .search-input-wrapper {
    position: relative;
    display: flex;
    gap: 0.75rem;
    max-width: 600px;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }

  .search-input {
    flex: 1;
    padding: 0.875rem 1.25rem;
    background: var(--bg-secondary);
    border: 2px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 1rem;
    transition: all 0.2s;
  }

  .search-input:focus {
    outline: none;
    border-color: var(--accent-color);
    background: var(--bg-tertiary);
  }

  .search-input::placeholder {
    color: var(--text-tertiary);
  }

  .search-button {
    padding: 0.875rem 2rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }

  .search-button:hover {
    background: var(--accent-hover);
  }

  .results-header {
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid var(--border-color);
  }

  .results-header h2 {
    color: var(--text-primary);
    margin: 0 0 0.5rem 0;
    font-size: 1.5rem;
  }

  .results-count {
    color: var(--text-secondary);
    margin: 0;
    font-size: 0.9375rem;
  }

  .results-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
  }

  .result-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    overflow: hidden;
    transition: all 0.2s;
  }

  .result-card:hover {
    border-color: var(--accent-color);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .result-thumbnail {
    width: 100%;
    aspect-ratio: 4 / 3;
    overflow: hidden;
    background: var(--bg-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .result-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .result-thumbnail.no-image {
    color: var(--text-tertiary);
    font-size: 0.875rem;
  }

  .result-content {
    padding: 1.25rem;
  }

  .result-type-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: var(--accent-color);
    color: white;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.75rem;
  }

  .result-type-badge.artwork-badge {
    background: #4caf50;
    color: white;
  }

  .result-type-badge.photo-badge {
    background: #2196f3;
    color: white;
  }

  .result-title {
    margin: 0 0 0.75rem 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  .result-title a {
    color: var(--text-primary);
    text-decoration: none;
    transition: color 0.2s;
  }

  .result-title a:hover {
    color: var(--accent-color);
  }

  .result-id {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin: 0.5rem 0;
  }

  .result-id code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.8125rem;
    font-weight: 600;
  }

  .result-meta {
    margin: 0.5rem 0;
    font-size: 0.9375rem;
    color: var(--text-secondary);
  }

  .meta-label {
    font-weight: 600;
    color: var(--text-primary);
    margin-right: 0.5rem;
  }

  .meta-link {
    color: var(--accent-color);
    text-decoration: none;
  }

  .meta-link:hover {
    text-decoration: underline;
  }

  .orphaned-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: rgba(255, 152, 0, 0.2);
    color: #ff9800;
    border-radius: 4px;
    font-size: 0.8125rem;
    font-weight: 500;
    margin-top: 0.5rem;
  }

  .error-message {
    padding: 1.5rem;
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid var(--error-color);
    border-radius: 8px;
    color: var(--error-color);
    margin-bottom: 2rem;
  }

  .error-message p {
    margin: 0;
  }

  .no-results {
    text-align: center;
    padding: 3rem 1rem;
    color: var(--text-secondary);
  }

  .no-results p {
    margin: 0.5rem 0;
  }

  .no-results strong {
    color: var(--text-primary);
  }

  .no-results-hint {
    font-size: 0.9375rem;
    color: var(--text-tertiary);
  }

  .autocomplete-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    margin-top: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    max-height: 400px;
    overflow-y: auto;
    z-index: 1000;
  }

  .autocomplete-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    width: 100%;
    text-align: left;
    background: transparent;
    border: none;
    border-bottom: 1px solid var(--border-color);
    cursor: pointer;
    transition: background 0.15s;
    color: var(--text-primary);
  }

  .autocomplete-item:last-child {
    border-bottom: none;
  }

  .autocomplete-item:hover,
  .autocomplete-item.selected {
    background: var(--bg-tertiary);
  }

  .suggestion-thumbnail {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
    border-radius: 4px;
    overflow: hidden;
    background: var(--bg-tertiary);
  }

  .suggestion-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .suggestion-icon {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-tertiary);
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--accent-color);
    text-transform: uppercase;
  }

  .suggestion-content {
    flex: 1;
    min-width: 0;
  }

  .suggestion-title {
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .suggestion-meta {
    font-size: 0.8125rem;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .suggestion-type {
    font-size: 0.75rem;
    color: var(--text-tertiary);
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }

  .suggestion-type.artwork-type {
    color: #4caf50;
  }

  .suggestion-type.photo-type {
    color: #2196f3;
  }

  .autocomplete-loading {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    margin-top: 0.5rem;
    padding: 0.75rem 1rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 0.875rem;
    text-align: center;
    z-index: 1000;
  }

  @media (max-width: 768px) {
    .search-container {
      padding: 1rem;
    }

    h1 {
      font-size: 2rem;
    }

    .search-input-wrapper {
      flex-direction: column;
    }

    .search-button {
      width: 100%;
    }

    .results-grid {
      grid-template-columns: 1fr;
    }

    .autocomplete-dropdown {
      position: relative;
      margin-top: 0.5rem;
    }
  }
</style>
