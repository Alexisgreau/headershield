from http.cookies import SimpleCookie


def test_cookie_parsing_basic():
    line = "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Strict"
    c = SimpleCookie()
    c.load(line)
    assert "sessionid" in c
    assert c["sessionid"].value == "abc"

