<script>
    export let data;
</script>

<h1>Artwork Upload</h1>

<!--Upload Form-->
<form method="POST">
    <label for="artist">Artist Name</label>
    <input type="text" name="artist_name" id="artist_name" />
    
    <label for="artwork_ttl">Title</label>
    <input type="text" name="artwork_ttl" id="artwork_ttl" />

    <label for="year_created">Date Created</label>
    <input type="number" name="year_created" id="year_created" min="1900" max="2100"/>

    <label for="storage_location">Storage Location</label>
    <input type="text" name="storage_location" id="storage_location" />

    <button type="submit">Add Artwork</button>
</form>

