<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

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
      <div class="stat-value">{data.stats.totalArtists ?? 0}</div>
      <div class="stat-label">Artists</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{data.stats.totalPhotos}</div>
      <div class="stat-label">Photos</div>
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

  .hero {
    text-align: center;
    padding: 4rem 2rem;
    margin-bottom: 3rem;
    background: var(--bg-primary);
    border-radius: 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
    border: 1px solid var(--border-color);
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
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 28px;
    height: 44px;
    border-radius: 22px;
    text-decoration: none;
    font-weight: 600;
    font-size: 1rem;
    transition: all 0.15s ease;
    border: none;
  }

  .btn-primary {
    background: var(--accent-color);
    color: white;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .btn-primary:hover {
    filter: brightness(1.05);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 122, 255, 0.3);
  }

  .btn-secondary {
    background: transparent;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn-secondary:hover {
    background: rgba(0, 122, 255, 0.08);
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