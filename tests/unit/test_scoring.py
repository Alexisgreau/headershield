from app.services.scoring import clamp, evaluate_header, is_csp_weak


def test_csp_missing_and_weak():
    status, penalty = evaluate_header("Content-Security-Policy", None)
    assert status == "MISSING" and penalty > 0
    assert is_csp_weak("default-src *")


def test_hsts_parsing():
    ok = evaluate_header("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")
    assert ok[0] == "OK" and ok[1] == 0
    weak = evaluate_header("Strict-Transport-Security", "max-age=10")
    assert weak[0] == "WEAK" and weak[1] > 0


def test_x_content_type_options():
    s, p = evaluate_header("X-Content-Type-Options", "nosniff")
    assert s == "OK" and p == 0
    s2, p2 = evaluate_header("X-Content-Type-Options", "")
    assert s2 == "WEAK"


def test_clamp():
    assert clamp(-10) == 0
    assert clamp(110) == 100

