import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { error } from '@sveltejs/kit';
import { extractErrorMessage } from '$lib/utils/errorMessages';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5000';

export const load = async ({ params, fetch }) => {
  const { id } = params;

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/artworks/${encodeURIComponent(id)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (response.status === 404) {
      throw error(404, 'Artwork not found. Suggestion: Check the artwork ID or browse artworks to find what you\'re looking for.');
    }

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artwork details');
      throw error(response.status, errorMessage);
    }

    const artwork = await response.json();
    return { artwork };

  } catch (err) {
    console.error('artwork detail load failed:', err);
    if (err.status) {
      throw err;
    }
    const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and try again.` 
      : 'Failed to load artwork. Suggestion: Refresh the page or try again later.';
    throw error(500, message);
  }
};
