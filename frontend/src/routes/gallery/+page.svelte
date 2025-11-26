<script>
    import { PUBLIC_API_BASE_URL } from '$env/static/public';
    export let data;
    //console.log(JSON.stringify(data));

    let artworkList = [];
    let viewableList = [];
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
        <button on:click={prevArtwork}>Previous</button>
        <button on:click={nextArtwork}>Next</button>
    </div>
{:else}
    <p>fetch did not work</p>
{/if}

<style>
    .gallery_cont {
        border: 0.05rem solid var(--border-color);
        width: 50%;
        margin: auto;
        padding: 0.5rem;
        display: flex;
    }

    .artist_info {
        border: 0.1rem solid var(--border-color);
        padding: 0.15rem;
        background-color: var(--bg-secondary);
    }

    .photo_placeholder {
        width: 95%;
        height: 60%;
        background-color: var(--bg-tertiary);
    }

    .artwork_image {
        display: flex;
        width: 200%;
        height: auto;
        justify-content: center;
        align-items: center;
    }
</style>
