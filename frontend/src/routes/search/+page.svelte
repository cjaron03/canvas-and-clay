 <!-- form taht implements server-side rendering -->

<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  // data is exported from load() in` routes/search/+page.server.js
  export let data;

  // helper to figure out the correct link for each result before rendering it
  const resolveHref = (entity, fallbackPrefix) => {
    if (!entity) return null;

    if (typeof entity === 'string') {
      return entity.startsWith('http') || entity.startsWith('/') ? entity : null;
    }

    if (entity.profile_url) return entity.profile_url;
    if (entity.url) return entity.url;
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
</script>

<h1>Search</h1>

<form method="GET" role="search">
  <label for="q">Keyword</label>
  <input
    id="q"
    name="q"
    type="search"
    value={data.q}
    placeholder="Search…"
    autocomplete="off"
  />
  <button type="submit">Search</button>
</form>

<!-- 
Renders the results based on Svelte template syntax + JS
-->
{#if data.error}
  <p>Error: {data.error}</p>
{:else if data.results?.length}
  <ul>
    {#each data.results as item}
      {#if item?.type === 'artwork'}
        <li>
          <div aria-hidden="true">
            {#if item?.thumbnail}
              <img src={getThumbnailUrl(item.thumbnail)} alt={`Thumbnail for ${item.title ?? 'artwork'}`} />
            {:else}
              <div>No thumbnail</div>
            {/if}
          </div>
          <div>
            {#if item?.title}
              <h2>
                {#if getArtworkHref(item)}
                  <a href={getArtworkHref(item)}>{item.title}</a>
                {:else}
                  <span>{item.title}</span>
                {/if}
              </h2>
            {/if}
            {#if item?.artist}
              <p>
                Artist:
                {#if item.artist_profile_url || getArtistHref(item.artist)}
                  <a href={item.artist_profile_url ?? getArtistHref(item.artist)}>
                    {typeof item.artist === 'string' ? item.artist : item.artist?.name}
                  </a>
                {:else}
                  <span>{typeof item.artist === 'string' ? item.artist : item.artist?.name}</span>
                {/if}
              </p>
            {:else if item?.artist_name}
              <p>Artist: {item.artist_name}</p>
            {/if}
            {#if item?.location}
              <p>
                Location:
                {#if typeof item.location === 'string'}
                  {item.location}
                {:else}
                  {#if item.location.profile_url || getLocationHref(item.location)}
                    <a href={item.location.profile_url ?? getLocationHref(item.location)}>
                      {item.location?.name}
                    </a>
                  {:else}
                    <span>{item.location?.name}</span>
                  {/if}
                {/if}
              </p>
            {/if}
          </div>
        </li>
      {:else if item?.type === 'artist'}
        <li>
          <div>
            <strong>Artist:</strong>
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
          </div>
        </li>
      {:else if item?.type === 'location'}
        <li>
          <div>
            <strong>Location:</strong>
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
          </div>
        </li>
      {:else if item?.type === 'photo'}
        <li>
          <div aria-hidden="true">
            {#if item?.thumbnail}
              <img src={getThumbnailUrl(item.thumbnail)} alt={`Photo: ${item.filename ?? 'image'}`} />
            {:else}
              <div>No thumbnail</div>
            {/if}
          </div>
          <div>
            <strong>Photo:</strong> {item.filename}
            {#if item?.orphaned}
              <span class="orphaned-badge">(Not associated with artwork)</span>
            {:else if item?.artwork}
              <p>
                Associated with artwork:
                {#if item.artwork.profile_url}
                  <a href={item.artwork.profile_url}>{item.artwork.title ?? item.artwork.id}</a>
                {:else}
                  <span>{item.artwork.title ?? item.artwork.id}</span>
                {/if}
              </p>
            {/if}
            {#if item?.url}
              <p>
                <a href={getThumbnailUrl(item.url)} target="_blank" rel="noopener noreferrer">View full size</a>
              </p>
            {/if}
            {#if item?.width && item?.height}
              <p class="photo-dimensions">{item.width} × {item.height} pixels</p>
            {/if}
          </div>
        </li>
      {:else}
        <li>
          <pre>{JSON.stringify(item, null, 2)}</pre>
        </li>
      {/if}
    {/each}
  </ul>
{:else if data.q?.trim()}
  <p>No results found.</p>
{/if}
