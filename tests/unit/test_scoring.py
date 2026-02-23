from app.services.scoring import clamp, evaluate_header


def test_csp_missing_and_weak():
    status, penalty, _ = evaluate_header("Content-Security-Policy", None)
    assert status == "MISSING" and penalty > 0

    status2, penalty2, details2 = evaluate_header(
        "Content-Security-Policy",
        "default-src *; script-src 'unsafe-inline' https:;",
    )
    assert status2 == "WEAK"
    assert penalty2 > 0
    assert details2


def test_csp_parser_tolerates_directives_without_value():
    status, penalty, _ = evaluate_header(
        "Content-Security-Policy",
        "default-src 'self'; upgrade-insecure-requests; object-src 'none'; base-uri 'self'",
    )
    assert status in {"OK", "WEAK"}
    assert penalty >= 0


def test_hsts_parsing():
    ok = evaluate_header("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")
    assert ok[0] == "OK" and ok[1] == 0
    weak = evaluate_header("Strict-Transport-Security", "max-age=10")
    assert weak[0] == "WEAK" and weak[1] > 0


def test_x_content_type_options():
    s, p, _ = evaluate_header("X-Content-Type-Options", "nosniff")
    assert s == "OK" and p == 0
    s2, p2, _ = evaluate_header("X-Content-Type-Options", "")
    assert s2 == "WEAK"
    assert p2 > 0


def test_legacy_headers_are_informative_by_default():
    missing_policy = evaluate_header("X-Permitted-Cross-Domain-Policies", None)
    assert missing_policy[0] == "INFO" and missing_policy[1] == 0

    weak_policy = evaluate_header("X-Permitted-Cross-Domain-Policies", "all")
    assert weak_policy[0] == "WEAK" and weak_policy[1] > 0

    clear_site_data_missing = evaluate_header("Clear-Site-Data", None)
    assert clear_site_data_missing[0] == "INFO" and clear_site_data_missing[1] == 0


def test_clamp():
    assert clamp(-10) == 0
    assert clamp(110) == 100
