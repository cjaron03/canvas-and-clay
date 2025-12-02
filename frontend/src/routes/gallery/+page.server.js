import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { extractErrorMessage } from '$lib/utils/errorMessages';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5000';

export const load = async ({ fetch }) => {

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
            const viewableArt = [];

            const artworksArray = Array.isArray(data.artworks)
                ? data.artworks
                : (Array.isArray(data.artworks?.array) ? data.artworks.array : []);

            artworksArray.forEach(artwork => {
                if (artwork?.is_viewable === true) {
                    viewableArt.push(artwork);
                }
            });
            //console.log(JSON.stringify(data));
            return {
                artworks: viewableArt,
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
