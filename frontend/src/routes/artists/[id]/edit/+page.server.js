import { API_BASE_URL } from '$env/static/private';
import { error } from '@sveltejs/kit';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ params, fetch }) => {
  const { id } = params;

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/artists/${encodeURIComponent(id)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (response.status === 404) {
      throw error(404, 'Artist not found. Suggestion: Verify the artist ID and try again.');
    }

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artist details');
      throw error(response.status, errorMessage);
    }

    const artist = await response.json();

    return { artist };
  } catch (err) {
    console.error('Failed to load artist edit data:', err);
    if (err.status) {
      throw err;
    }
    const message = err instanceof Error
      ? `${err.message}. Suggestion: Check your internet connection and refresh the page.`
      : 'Failed to load artist edit form data. Suggestion: Refresh the page or try again later.';
    throw error(500, message);
  }
};
