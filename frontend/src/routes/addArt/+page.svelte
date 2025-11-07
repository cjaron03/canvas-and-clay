<script>
    export let form;
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

<!--
{#if form?.success}
    <p>{form.message}</p>
{:else }
    <p style="color: red;">{form.message}</p>
{/if}
-->

<style>
    form {
        width: fit-content;
        margin: auto;
        display: flex;
        flex-direction: column;
        background-color: #454545;
        padding: 2em;
        border: 0.1em solid black;
        border-radius: 3em;
        justify-content: space-between;
        gap: 1em;
    }
</style>

