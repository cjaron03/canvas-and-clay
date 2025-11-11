import { API_BASE_URL } from '$env/static/private';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ fetch }) => {
  try {
    // Fetch recent artworks and stats in parallel
    const [artworksResponse] = await Promise.all([
      fetch(`${API_BASE_URL}/api/artworks?per_page=6&page=1`, {
        headers: {
          accept: 'application/json'
        }
      })
    ]);

    let recentArtworks = [];
    let stats = {
      totalArtworks: 0,
      totalArtists: 0,
      totalPhotos: 0
    };

    if (artworksResponse.ok) {
      const artworksData = await artworksResponse.json();
      recentArtworks = artworksData.artworks || [];
      stats.totalArtworks = artworksData.pagination?.total || 0;
    } else {
      const errorMessage = await extractErrorMessage(artworksResponse, 'load home page data');
      return {
        recentArtworks: [],
        stats: {
          totalArtworks: 0,
          totalArtists: 0,
          totalPhotos: 0
        },
        error: errorMessage
      };
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

