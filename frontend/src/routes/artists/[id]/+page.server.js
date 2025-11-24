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
                throw error(404, 'Artist not found.');
                }
        
            if (!response.ok) {
                const errorMessage = await extractErrorMessage(response, 'load artwork details');
                throw error(response.status, errorMessage);
            }

        const artist = await response.json();
        return { artist };

    }
    catch (err) {
    console.error('artist detail load failed:', err);
    // For errors like 404 that are already formatted for SvelteKit's HTTP handler, 
    // err.status passes the full error code and message
    if (err.status) {
      throw err;
    }
    const message = err instanceof Error 
      ? `${err.message}.` 
      : 'Failed to load artist.';
    throw error(500, message);
  }
};