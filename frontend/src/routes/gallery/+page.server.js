import { API_BASE_URL } from '$env/static/private';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ fetch}) => {

    try {
        const response = await fetch(
            `${API_BASE_URL}/api/artworks?`,
            {
                headers: {
                    accept: 'application/json'
                }
            }
        )

        if (response.ok){
            const data = await response.json();
            //console.log(JSON.stringify(data));
            return {
                artworks: data.artworks,
                pagination: data.pagination,
                error: null
            };
        }
        else {
            const errorMessage = await extractErrorMessage(response, 'load artworks')
            return {
                artworks: [],
                pagination: null,
                error: errorMessage
            };
        }

    } catch(err) {
        console.error('artwork load failed:', err);
        const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and try again.` 
      : 'Unexpected error while loading artworks. Suggestion: Refresh the page or try again later.';
        return {
            artworks: [],
            pagination: null,
            error: message
        };
    }
}