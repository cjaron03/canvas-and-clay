"""Testing add_artwork.py

for ease of testing use to open python shell
docker exec -it canvas_backend /bin/bash  

run pytest                  
root@7060a61d3105:/app# PYTHONPATH=. pytest tests/test_add_artwork.py -v
"""
import pytest 
from unittest.mock import MagicMock, patch
from add_artwork import add_artwork
from app import Artwork
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Helper function to create a mock query that returns a value or None
def make_mock_query(return_value=None):
    mock_query = MagicMock()
    mock_query.filter_by.return_value.first.return_value = return_value
    return mock_query

@pytest.fixture
def mock_session():
    # Patch the db.session object in app
    with patch("app.db.session") as session_mock:
        yield session_mock

def test_add_artwork_success(mock_session):
    """Test successful addition of artwork with valid artist and storage"""
    # Mock Artist and Storage exist
    mock_session.query.side_effect = [
        make_mock_query(return_value=MagicMock(id="A0000001")),  # Artist
        make_mock_query(return_value=MagicMock(id="S000001")),   # Storage
        make_mock_query(return_value=None)  # Artwork ID is unique
    ]

    # Mock session methods
    mock_session.add = MagicMock()
    mock_session.commit = MagicMock()
    mock_session.refresh = MagicMock()

    new_artwork = add_artwork(
        "Unit Test Artwork",
        "Oil",
        "2023-11-04",
        "24x36in",
        "A0000001",
        "S000001"
    )

    # Verify the return type and IDs
    assert isinstance(new_artwork, Artwork)
    assert new_artwork.artist_id == "A0000001"
    assert new_artwork.storage_id == "S000001"

    # Verify session methods called
    mock_session.add.assert_called_once_with(new_artwork)
    mock_session.commit.assert_called_once()
    mock_session.refresh.assert_called_once_with(new_artwork)

def test_add_artwork_artist_missing(mock_session):
    """Test ValueError raised when artist does not exist"""
    mock_session.query.side_effect = [
        make_mock_query(return_value=None),  # Artist missing
        make_mock_query(return_value=MagicMock(id="S000001"))
    ]

    with pytest.raises(ValueError) as excinfo:
        add_artwork(
            "Missing Artist",
            "Oil",
            "2023-11-04",
            "24x36in",
            "A9999999",
            "S000001"
        )
    assert "Given Artist ID not in Artist Table" in str(excinfo.value)

def test_add_artwork_storage_missing(mock_session):
    """Test ValueError raised when storage does not exist"""
    mock_session.query.side_effect = [
        make_mock_query(return_value=MagicMock(id="A0000001")),  # Artist exists
        make_mock_query(return_value=None)  # Storage missing
    ]

    with pytest.raises(ValueError) as excinfo:
        add_artwork(
            "Missing Storage",
            "Oil",
            "2023-11-04",
            "24x36in",
            "A0000001",
            "S999999"
        )
    assert "Given Storage ID not in Storage Table" in str(excinfo.value)

def test_artwork_id_unique_check(mock_session):
    """Test that add_artwork retries to generate a unique artwork_num"""
    first_artwork_exists = MagicMock()

    mock_session.query.side_effect = [
        make_mock_query(return_value=MagicMock(id="A0000001")),  # Artist
        make_mock_query(return_value=MagicMock(id="S000001")),   # Storage
        make_mock_query(return_value=first_artwork_exists),      # First artwork ID exists
        make_mock_query(return_value=None)                       # Second ID is unique
    ]

    # Mock session methods
    mock_session.add = MagicMock()
    mock_session.commit = MagicMock()
    mock_session.refresh = MagicMock()

    new_artwork = add_artwork(
        "Unique ID Test",
        "Acrylic",
        "2023-11-04",
        "18x24in",
        "A0000001",
        "S000001"
    )

    # Verify session methods called
    mock_session.add.assert_called_once_with(new_artwork)
    mock_session.commit.assert_called_once()
    mock_session.refresh.assert_called_once_with(new_artwork)

    # Ensure the new ID is not the same as the existing one
    assert new_artwork.artwork_num != first_artwork_exists.id

