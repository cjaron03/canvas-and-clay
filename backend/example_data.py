""" Example data for populating the database
    last modified: 10/27/25 (MK)
    TO DO: convert data into dicts so dont have to convert tuples
           in alembic file
"""
from app import db

artist_data = [
    ("A0000001", "Alice", "Astro", "abc123@gmail.com", "aliceastro_23", "I am a painter", "(123)-456-7890"),
    ("A0000002", "Bob", "Benson", "def456@gmail.com", "bobmakesthings", "Follow my insta", "(098)-765-4321"),
    ("A0000003", "Cath", "Caine", "cece12@yahoo.com", "cecedraws.com", "I make so much ", "(843)-416-7010"),
    ("A0000004", "Darla", "Duke", "dduke90@yahoo.com", "darlingdars_22", "I stream all the time! I make sculptures",
     "(707)-775-4921"),
    ("A0000005", "Edna", "Eelse", "incredible@yahoo.com", "ednaeelse.net", "Go to my site for more", "(223)-676-7870"),
    ("A0000006", "Frank", "Frankford", "frank11@gmail.com", "frank890", "I post things on insta", "(998)-554-4321"),
    ("A0000007", "Gary", "Garrenson", "artist12@gmail.com", "garrenson.gary", "Here is my instagram",
      "(298)-265-4321"),
    ("A0000008", "Hary", "Howelle", "hhowelle@comcast.net", "aliceastro_23", "I am a sculpter", "(123)-456-7890"),
    ("A0000009", "Iris", "Irene", "fluffypuppy@hotmail.com", "aliceastro_23",
      "I am from LA and am excited to paint!", "(333)-422-7890"),
    ("A0000010", "Joseph", "Jenkins", "joejenks@gmail.com", "jenkinspaints.com", "I use watercolor", "(707)-706-4121"),
    ("A0000011", "Karen", "Kain", "karenkaren@gmail.com", "karensmugs_44", "Follow my insta and see my pottery",
      "(328)-543-4321"),
    ("A0000012", "Larry", "Lamenson", "llarry@gmail.com", "laryiscool", 
     "I am a painter on instagram. I am Originally from Texas.",
      "(723)-021-5987")
]
artwork_data = [
    #"A0000001"
    ("AW000001", "The big dog", "Acrylic", "2015-09-21", "36x48in", "A0000001", "S000001"),
    ("AW000002", "The small cat", "Acrylic", "2015-09-02", "10x12in", "A0000001", "S000002"),
    #"A0000002"
    ("AW000003", "Pink Clouds", "Watercolor", "2018-10-01", "10x12in", "A0000002", "S000002"),
    ("AW000004", "Blue Skies", "Acrylic", "2018-10-12", "10x18in", "A0000002", "S000002"),
    ("AW000005", "Green Waters", "Acrylic", "2018-12-02", "8x11in", "A0000002", "S000002"),
    #"A0000003"
    ("AW000006", "Funny", "Oil", "2017-11-03", "24x36in", "A0000003", "S000003"),
    #"A0000004"
    ("AW000007", "Untitled", "Clay", "2015-09-21", "3x3x3ft", "A0000004", "S000001"),
    ("AW000008", "Windy road", "Acrylic", "2015-09-02", "10x12in", "A0000004", "S000002"),
    ("AW000009", "Raincoat", "Watercolor", "2016-10-10", "24x36in", "A0000004", "S000004"),
    ("AW000010", "Jackets", "Oil", "2016-10-21", "36x48in", "A0000004", "S000003"),
    ("AW000011", "Big Day", "Oil", "2016-09-02", "10x12in", "A0000004", "S000004"),
    #"A0000005 will have no data for testing purposes
    #"A0000006"
    ("AW000012", "Wonder", "Watercolor", "2019-04-01", "10x12in", "A0000006", "S000004"),
    ("AW000013", "Plunder", "Watercolor", "2019-04-19", "10x10in", "A0000006", "S000004"),
    #"A0000007"
    ("AW000014", "Run fast", "Oil", "2019-09-17", "48x48in", "A0000007", "S000001"),
    #"A0000008"
    ("AW000015", "Frogs", "Clay", "2018-10-01", "2x2x2ft", "A0000008", "S000004"),
    ("AW000016", "Toads", "Ceramic", "2015-09-21", "3x2x4ft", "A0000008", "S000004"),
    #A0000009
    ("AW000017", "Sunset", "Ink", "2018-06-10", "12x36in", "A0000009", "S000003"),
    #A0000010
    ("AW000018", "Pencil Case", "Ink", "2019-03-01", "24x36in", "A0000010", "S000003"),
    ("AW000019", "Untitled", "Digital", "2019-03-21", "10x12in", "A0000010", "S000003"),
    #A0000011 will have no data for testing purposes
    #A0000012
    ("AW000020", "Computers", "Ink", "2016-10-03", "8x11in", "A0000012", "S000004"),
    ("AW000021", "Books", "Ink", "2016-11-11", "24x36in", "A0000012", "S000003")
]
storage_data = [
    ("S000001", "Main Building", "flat_file" ),
    ("S000002", "Satellite Building", "flat_file" ),
    ("S000003", "Extra", "rack" ),
    ("S000004", "Gallery", "Wall" ),
    # for have no data for testing purposes
    ("S000005", "Shed", "rack")
]
flatfile_data = [
    # S00001
    # for ease of testing artworks in S00001 
    # AW00001 AW00007 AW00014
    ("S000001", "LC01"),
    # S00002
    # for ease of testing artoworks in S00002
    # AW00002 AW00003 AW00004 AW00005 AW00008
    ("S000002", "LC02")
]

wallspace_data = [
    # S00004
    # for ease of teting artworkds in S00004
    # AW00009 AW00011 AW00012 AW00013 AW00015 AW00016 AW00020
    ("S000004", "West")
]

rack_data = [
    # S00003
    # for ease of testing artworkds in S00003
    # AW00005 AW00010 AW00017 AW00018 AW00019 AW00021
    ("S000003", "RN01")
]