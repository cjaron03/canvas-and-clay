import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ fetch }) => {
  try {
    // Fetch recent artworks and public stats in parallel
    const [artworksResponse, statsResponse] = await Promise.all([
      fetch(`${PUBLIC_API_BASE_URL}/api/artworks?per_page=6&page=1`, {
        headers: {
          accept: 'application/json'
        }
      }),
      fetch(`${PUBLIC_API_BASE_URL}/api/stats/overview`, {
        headers: {
          accept: 'application/json'
        }
      })
    ]);

    let recentArtworks = [];
    let stats = {
      totalArtworks: 0,
      totalArtists: 0,
      totalPhotos: 0,
      artistUsers: 0
    };

    if (artworksResponse.ok) {
      const artworksData = await artworksResponse.json();
      recentArtworks = artworksData.artworks || [];
      stats.totalArtworks = artworksData.pagination?.total || 0;
      stats.totalPhotos = artworksData.total_photos || 0;
    }

    if (statsResponse.ok) {
      const statsData = await statsResponse.json();
      const counts = statsData?.counts || {};
      stats.totalArtists = counts.artists || 0;
      stats.artistUsers = counts.artist_users || 0;
      if (counts.photos !== undefined) {
        stats.totalPhotos = counts.photos;
      }
    } else {
      const errorMessage = await extractErrorMessage(statsResponse, 'load stats');
      console.warn('Stats fetch failed for home page:', errorMessage);
    }

    return {
      recentArtworks,
      stats,
      error: null
    };
  } catch (err) {
    console.error('Home page load failed:', err);
    const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and refresh the page.` 
      : 'Failed to load home page data. Suggestion: Refresh the page or try again later.';
    return {
      recentArtworks: [],
      stats: {
        totalArtworks: 0,
        totalArtists: 0,
        totalPhotos: 0
      },
      error: message
    };
  }
};
