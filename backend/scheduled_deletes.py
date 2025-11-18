from app import db, app, Artist, Artwork, ArtworkPhoto
from upload_utils import delete_photo_files
from datetime import datetime, timedelta, timezone

def scheduled_artwork_deletion():
    """ A scheduled deletion of artworks that have been
        soft deleted for more than 30 days.

    Makes use of APScheduler, designed to run in the 
    background of app.py

    Returns:
     - Nothing, but will log the successfull deletion
        under app.logger.info
     - In the case of error, it will be logged along with the error
        under app.logger.exception or app.logger.warning
    """
    cutoff_date = datetime.now(timezone.utc).date() - timedelta(days=30)

    # Grab soft-deleted artworks that have been deleted for over 30 days
    old_artworks = Artwork.query.filter(
        Artwork.is_deleted==True,
        Artwork.date_deleted <= cutoff_date).all()
    
    # Tracking track of artwork and photo counts for logging audit
    total_artworks = len(old_artworks)
    total_photos = 0
    try:
        for artwork in old_artworks:
            # Grab photos associated with artwork
            old_photos = ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).all()
            total_photos += len(old_photos)

            for photo in old_photos:
                # Delete photo files from system
                try:
                    delete_photo_files(photo.file_path, photo.thumbnail_path)
                except Exception as e:
                    app.logger.warning(f"Failed to delete photo files for {photo.photo_id}: {e}")
                
            # Delete photo from ArtworkPhoto
            ArtworkPhoto.query.filter_by(artwork_num=artwork.artwork_num).delete()

            # Delete artwork from Artwork
            db.session.delete(artwork)
    
        db.session.commit()
        
        # Log the deletion and total count
        app.logger.info(f"Scheduled deletion of {total_artworks} artworks " 
                        f"and {total_photos} photos older than 30 days was successful.")


    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Scheduled artwork deletion failed.")         

