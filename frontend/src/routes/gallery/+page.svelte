<script>
    import { PUBLIC_API_BASE_URL } from '$env/static/public';
    import { auth } from '$lib/stores/auth';
    export let data;

    let currArtIndex = 0;

    const getThumbnailUrl = (thumbnail) => {
        if (!thumbnail) return null;
        if (thumbnail.startsWith('http')) return thumbnail;
        return `${PUBLIC_API_BASE_URL}${thumbnail}`;
    };

    function nextArtwork(){
        currArtIndex = (currArtIndex - 1 + data.artworks.length) % data.artworks.length;
    }
    function prevArtwork(){
        currArtIndex = (currArtIndex + 1) % data.artworks.length;
    }
    
</script>

{#if data.artworks && data.artworks.length > 0}
    <div class="gallery_cont">
        <h1>{data.artworks[currArtIndex].title}</h1>
        {#if data.artworks[currArtIndex].primary_photo?.thumbnail_url}
            <img 
                src={getThumbnailUrl(data.artworks[currArtIndex].primary_photo.thumbnail_url)}
                alt={data.artworks[currArtIndex].title}
                class="artwork_image"
            />
        {:else}
            <div class="photo_placeholder">no image</div>
        {/if}
        <div class="artist_info">
            <p>Artist name: {data.artworks[currArtIndex].artist.name}</p>
            <p>Artist email: {data.artworks[currArtIndex].artist.email}</p>
        </div>
        <div class="button_container">
            <button class="gallery_button" on:click={prevArtwork}>Previous</button>
            <button class="gallery_button" on:click={nextArtwork}>Next</button>
        </div>
    </div>
    {#if $auth.isAuthenticated}
        {#if $auth.user?.role === 'admin'}
            <div class="button_container">
                <a href="/artworks/{data.artworks[currArtIndex].id}/edit" class="gallery_button">Edit Artwork</a>
            </div>
        {/if}
    {/if}  
{:else}
    <p>fetch did not work</p>
{/if}

<style>
    .gallery_cont {
        border: 0.05rem solid var(--border-color);
        width: 95%;
        margin: auto;
        margin-top: 0.5rem;
        padding: 0.5rem;
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    .artist_info {
        border: 0.1rem solid var(--border-color);
        margin: 0.5rem;
        padding: 0.5rem;
        background-color: var(--bg-secondary);
    }

    .photo_placeholder {
        width: 95%;
        height: 25rem;
        display: flex;
        justify-content: center;
        align-items: center;
        background-color: var(--bg-tertiary);
    }

    .artwork_image {
        display: flex;
        width: 95%;
        justify-content: center;
        align-items: center;
    }

    .button_container {
        display: flex;
        flex-direction: row;
    }

    .gallery_button {
        margin: 0.5rem;
        padding: 1.5rem;
        width: 8rem;
        border: 0.15rem solid var(--border-color);
        border-radius: 1rem;
        color: white;
        text-decoration: none;
        background-color: var(--accent-color);
        cursor: pointer;
    }

    .gallery_button:hover {
        background-color: var(--accent-hover);
    }
</style>
