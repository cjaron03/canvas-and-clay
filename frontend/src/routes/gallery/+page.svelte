<script>
    export let data;
    
    let artworkList = [];
    let viewableList = [];
    let currArtIndex = 0;

    const getThumbnailUrl = (thumbnail) => {
        if (!thumbnail) return null;
        if (thumbnail.startsWith('http')) return thumbnail;
        return `${PUBLIC_API_BASE_URL}${thumbnail}`;
    };

    function nextArtwork(){
        currArtIndex = (currArtIndex - 1 + viewableList.length) % viewableList.length;
    }
    function prevArtwork(){
        currArtIndex = (currArtIndex + 1) % viewableList.length;
    }

    artworkList = data.artworks;
    artworkList.array.forEach(artwork => {
        if(artwork.is_viewable === 'TRUE'){
            viewableList.push(artwork);
        }
    });
    
</script>

<div class="gallery_cont">
    <button on:click={prevArtwork}>Previous</button>
    <img 
        src={getThumbnailUrl(viewableList[currArtIndex].primary_photo.thumbnail_url)}
        alt={viewableList[currArtIndex].title}
    />
    <p>{viewableList[currArtIndex].artist_info.name}</p>
    <button on:click={nextArtwork}>Next</button>
</div>