from project import temp_list, urlparse, confirm
import os.path


test_list = [
    ["url1", "login1", "password1", "note1"],
    ["url2", "login2", "password2", "note2"],
]


def test_urlparse():
    assert (
        urlparse("https://se-pa-code50-112631415.github.dev/").hostname
        == "se-pa-code50-112631415.github.dev"
    )
    assert urlparse("https://www.youtube.com/").hostname == "www.youtube.com"
    assert urlparse("https://www.google.pl/").hostname == "www.google.pl"
    assert urlparse("youtube.com").hostname == "youtube.com"
    assert urlparse("www.google.com/gmail").hostname == "www.google.com"


def test_temp_list():
    filename = os.path.join(os.path.dirname(__file__), "test_database.csv")
    assert temp_list(filename) == test_list


def test_confirm():
    assert confirm("Yes") == True
    assert confirm("yes") == True
    assert confirm("ye") == True
    assert confirm("y") == True
    assert confirm("YeS") == True
    assert confirm("") == None
    assert confirm("No") == None
    assert confirm("532532") == None
