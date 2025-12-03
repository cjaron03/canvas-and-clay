<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';

  export let data;

  const getThumbnailUrl = (thumbnail) => {
    if (!thumbnail) return null;
    if (thumbnail.startsWith('http')) return thumbnail;
    return `${PUBLIC_API_BASE_URL}${thumbnail}`;
  };
</script>

<div class="home-container">
  <section class="hero">
    <h1>Canvas and Clay</h1>
    <p class="subtitle">Art Collection Management System</p>
    <p class="description">
      Manage your art collection with ease. Track artworks, artists, storage locations, and photos all in one place.
    </p>
    <div class="hero-actions">
      <a href="/artworks" class="btn-primary">Browse Artworks</a>
      <a href="/artists" class="btn-secondary">Browse Artists</a>
    </div>
  </section>

  <section class="stats">
    <div class="stat-card">
      <div class="stat-value">{data.stats.totalArtworks}</div>
      <div class="stat-label">Artworks</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{data.stats.artistUsers ?? data.stats.totalArtists ?? 0}</div>
      <div class="stat-label">Artists</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{data.stats.totalPhotos}</div>
      <div class="stat-label">Photos</div>
    </div>
  </section>

  <section class="quick-actions">
    <h2>Quick Actions</h2>
    <div class="actions-grid">
      <a href="/artworks" class="action-card">
        <div class="action-icon">Browse</div>
        <h3>Browse Artworks</h3>
        <p>View and manage your art collection</p>
      </a>
      <a href="/artists" class="action-card">
        <div class="action-icon">Artists</div>
        <h3>Artists</h3>
        <p>Find and manage artists.</p>
      </a>
      {#if $auth.isAuthenticated}
        {#if $auth.user?.role === 'admin'}
          <a href="/uploads" class="action-card">
            <div class="action-icon">Upload</div>
            <h3>Upload Photos</h3>
            <p>Add photos to your artworks</p>
          </a>
          <a href="/artworks/new" class="action-card">
            <div class="action-icon">Add</div>
            <h3>Add Artwork</h3>
            <p>Create a new artwork entry</p>
          </a>
        {/if}
      {:else}
        <a href="/login" class="action-card">
          <div class="action-icon">Login</div>
          <h3>Login</h3>
          <p>Sign in to manage your collection</p>
        </a>
      {/if}
    </div>
  </section>

  {#if data.recentArtworks && data.recentArtworks.length > 0}
    <section class="recent-artworks">
      <div class="section-header">
        <h2>Recent Artworks</h2>
        <a href="/artworks" class="view-all">View All →</a>
      </div>
      <div class="artwork-grid">
        {#each data.recentArtworks as artwork}
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
              <p class="artwork-id"><code>{artwork.id}</code></p>
              <p class="artist-name">{artwork.artist?.name || 'Unknown Artist'}</p>
              {#if artwork.medium}
                <p class="medium">{artwork.medium}</p>
              {/if}
            </div>
          </a>
        {/each}
      </div>
    </section>
  {/if}
</div>

<style>
  .home-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1.5rem;
  }

  .hero {
    text-align: center;
    padding: 2rem 1rem;
    margin-bottom: 2rem;
  }

  .hero h1 {
    font-size: 3rem;
    font-weight: 700;
    margin: 0 0 1rem 0;
    color: var(--text-primary);
    background: linear-gradient(135deg, var(--accent-color) 0%, var(--accent-hover) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .subtitle {
    font-size: 1.5rem;
    color: var(--text-secondary);
    margin: 0 0 1rem 0;
    font-weight: 500;
  }

  .description {
    font-size: 1.125rem;
    color: var(--text-secondary);
    max-width: 600px;
    margin: 0 auto 2rem;
    line-height: 1.6;
  }

  .hero-actions {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
  }

  .btn-primary,
  .btn-secondary {
    padding: 0.75rem 2rem;
    border-radius: 6px;
    text-decoration: none;
    font-weight: 600;
    font-size: 1rem;
    transition: all 0.2s;
    display: inline-block;
  }

  .btn-primary {
    background: var(--accent-color);
    color: white;
  }

  .btn-primary:hover {
    background: var(--accent-hover);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(90, 159, 212, 0.3);
  }

  .btn-secondary {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn-secondary:hover {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
    transform: translateY(-2px);
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .stat-card {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1.25rem;
    text-align: center;
    transition: transform 0.2s;
  }

  .stat-card:hover {
    transform: translateY(-2px);
  }

  .stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent-color);
    margin-bottom: 0.25rem;
  }

  .stat-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 500;
  }

  .recent-artworks {
    margin-bottom: 2rem;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .section-header h2 {
    font-size: 1.5rem;
    color: var(--text-primary);
    margin: 0;
  }

  .view-all {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    transition: color 0.2s;
  }

  .view-all:hover {
    color: var(--accent-hover);
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

  .artist-name {
    color: var(--accent-color);
    font-weight: 500;
    margin: 0 0 0.25rem 0;
  }

  .medium {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0;
  }

  .quick-actions {
    margin-bottom: 2rem;
  }

  .quick-actions h2 {
    font-size: 1.5rem;
    color: var(--text-primary);
    margin: 0 0 1rem 0;
  }

  .actions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .action-card {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 1rem;
    text-decoration: none;
    color: inherit;
    transition: all 0.2s;
    border: 1px solid transparent;
  }

  .action-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent-color);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
  }

  .action-icon {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--accent-color);
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .action-card h3 {
    color: var(--text-primary);
    margin: 0 0 0.25rem 0;
    font-size: 1rem;
  }

  .action-card p {
    color: var(--text-secondary);
    margin: 0;
    font-size: 0.8125rem;
    line-height: 1.4;
  }

  @media (max-width: 768px) {
    .hero h1 {
      font-size: 2rem;
    }

    .subtitle {
      font-size: 1.25rem;
    }

    .description {
      font-size: 1rem;
    }

    .hero-actions {
      flex-direction: column;
      align-items: stretch;
    }

    .btn-primary,
    .btn-secondary {
      width: 100%;
      text-align: center;
    }

    .artwork-grid {
      grid-template-columns: 1fr;
    }

    .actions-grid {
      grid-template-columns: 1fr;
    }
  }
</style>