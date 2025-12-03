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
        <div class="action-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
        </div>
        <h3>Browse Artworks</h3>
        <p>View and manage your art collection</p>
      </a>
      <a href="/artists" class="action-card">
        <div class="action-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
        </div>
        <h3>Artists</h3>
        <p>Find and manage artists.</p>
      </a>
      {#if $auth.isAuthenticated}
        {#if $auth.user?.role === 'admin'}
          <a href="/uploads" class="action-card">
            <div class="action-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
            </div>
            <h3>Upload Photos</h3>
            <p>Add photos to your artworks</p>
          </a>
          <a href="/artworks/new" class="action-card">
            <div class="action-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
            </div>
            <h3>Add Artwork</h3>
            <p>Create a new artwork entry</p>
          </a>
        {/if}
      {:else}
        <a href="/login" class="action-card">
          <div class="action-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path><polyline points="10 17 15 12 10 7"></polyline><line x1="15" y1="12" x2="3" y2="12"></line></svg>
          </div>
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
                <div class="no-image">
                  <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
                </div>
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
    padding: 4rem 2rem;
    margin-bottom: 3rem;
    background: var(--bg-secondary);
    border-radius: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  }

  .hero h1 {
    font-size: 3.5rem;
    font-weight: 800;
    margin: 0 0 1rem 0;
    color: var(--text-primary);
    background: linear-gradient(135deg, var(--accent-color) 0%, var(--accent-hover) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.2;
  }

  .subtitle {
    font-size: 1.5rem;
    color: var(--text-primary);
    margin: 0 0 1rem 0;
    font-weight: 600;
  }

  .description {
    font-size: 1.125rem;
    color: var(--text-secondary);
    max-width: 600px;
    margin: 0 auto 2.5rem;
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
    padding: 0.875rem 2rem;
    border-radius: 8px;
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
    background: white;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn-secondary:hover {
    background: var(--bg-tertiary);
    border-color: var(--accent-color);
    transform: translateY(-2px);
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1.5rem;
    margin-bottom: 4rem;
  }

  .stat-card {
    background: var(--bg-secondary);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    transition: transform 0.2s;
    border: 1px solid var(--border-color);
  }

  .stat-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
  }

  .stat-value {
    font-size: 2.5rem;
    font-weight: 800;
    color: var(--accent-color);
    margin-bottom: 0.25rem;
    line-height: 1;
  }

  .stat-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 600;
  }

  .recent-artworks {
    margin-bottom: 3rem;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .section-header h2 {
    font-size: 1.75rem;
    color: var(--text-primary);
    margin: 0;
    font-weight: 700;
  }

  .view-all {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 600;
    transition: color 0.2s;
    display: flex;
    align-items: center;
    gap: 0.25rem;
  }

  .view-all:hover {
    color: var(--accent-hover);
  }

  .artwork-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 2rem;
  }

  .artwork-card {
    background: var(--bg-secondary);
    border-radius: 12px;
    overflow: hidden;
    text-decoration: none;
    color: inherit;
    transition: all 0.2s;
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    border: 1px solid var(--border-color);
  }

  .artwork-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
    border-color: var(--accent-color);
  }

  .artwork-thumbnail {
    width: 100%;
    height: 240px;
    background: var(--bg-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    position: relative;
  }

  .artwork-thumbnail img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    transition: transform 0.5s;
  }

  .artwork-card:hover .artwork-thumbnail img {
    transform: scale(1.05);
  }

  .no-image {
    color: var(--text-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    height: 100%;
  }

  .artwork-info {
    padding: 1.25rem;
  }

  .artwork-info h3 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.125rem;
    font-weight: 600;
    line-height: 1.4;
  }

  .artwork-id {
    margin: 0 0 0.75rem 0;
    font-size: 0.75rem;
  }

  .artwork-id code {
    background: var(--bg-tertiary);
    color: var(--accent-color);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-family: 'Menlo', 'Monaco', monospace;
    font-weight: 600;
  }

  .artist-name {
    color: var(--text-primary);
    font-weight: 500;
    margin: 0 0 0.25rem 0;
  }

  .medium {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0;
  }

  .quick-actions {
    margin-bottom: 4rem;
  }

  .quick-actions h2 {
    font-size: 1.75rem;
    color: var(--text-primary);
    margin: 0 0 1.5rem 0;
    font-weight: 700;
  }

  .actions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1.5rem;
  }

  .action-card {
    background: var(--bg-secondary);
    border-radius: 12px;
    padding: 1.5rem;
    text-decoration: none;
    color: inherit;
    transition: all 0.2s;
    border: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    align-items: flex-start;
  }

  .action-card:hover {
    transform: translateY(-4px);
    border-color: var(--accent-color);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
  }

  .action-icon {
    color: var(--accent-color);
    margin-bottom: 1rem;
    padding: 0.75rem;
    background: rgba(90, 159, 212, 0.1);
    border-radius: 12px;
    display: inline-flex;
  }

  .action-card h3 {
    color: var(--text-primary);
    margin: 0 0 0.5rem 0;
    font-size: 1.125rem;
    font-weight: 600;
  }

  .action-card p {
    color: var(--text-secondary);
    margin: 0;
    font-size: 0.9rem;
    line-height: 1.5;
  }

  @media (max-width: 768px) {
    .home-container {
      padding: 1rem;
    }

    .hero {
      padding: 3rem 1.5rem;
      border-radius: 12px;
    }

    .hero h1 {
      font-size: 2.5rem;
    }

    .subtitle {
      font-size: 1.25rem;
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
    
    .stats {
      grid-template-columns: 1fr;
      gap: 1rem;
    }

    .artwork-grid {
      grid-template-columns: 1fr; /* Single column on mobile for clarity */
    }

    .actions-grid {
      grid-template-columns: 1fr;
    }
  }
</style>