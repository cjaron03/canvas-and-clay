<script>
    export let data;
    
    let artworkList = [];
    let viewableList = [];

    const getThumbnailUrl = (thumbnail) => {
        if (!thumbnail) return null;
        if (thumbnail.startsWith('http')) return thumbnail;
        return `${PUBLIC_API_BASE_URL}${thumbnail}`;
    };

    artworkList = data.artworks;
    artworkList.array.forEach(artwork => {
        if(artwork.is_viewable == 'TRUE'){
            viewableList.push(artwork);
        }
    });
    let currArtIndex = $state(0);
    let currArtwork = $derived(viewableList[currArtIndex]);
    
</script>

<div class="gallery_cont">
    {#if currArtIndex > 0}
        <button on:click={() => (currArtIndex--)}>Previous</button>
    {/if}
    <img 
        src={getThumbnailUrl(currArtwork.primary_photo.thumbnail_url)}
        alt={currArtwork.title}
    />
    <p>{currArtwork.artist_info.name}</p>
    {#if currArtIndex < (viewableList.length - 1)}
        <button on:click={() => (currArtIndex++)}>Next</button>
    {/if}
</div>