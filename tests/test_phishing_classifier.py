from phishing_detector.classifier import _parse_classification


def test_well_formed_reply():
    r = _parse_classification(
        "LABEL: PHISHING\nCONFIDENCE: 92\nINDICATORS: urgent tone, spoofed domain\nREASONING: Fake bank link."
    )
    assert r.label == "phishing"
    assert r.confidence == 92
    assert r.indicators == ["urgent tone", "spoofed domain"]


def test_malformed_reply_falls_back():
    r = _parse_classification("I think this is probably fine?")
    assert r.label == "unknown"
    assert r.confidence == 50
    assert r.indicators == []


def test_bad_confidence_keeps_default():
    assert _parse_classification("LABEL: legitimate\nCONFIDENCE: high").confidence == 50


def test_none_indicators():
    assert _parse_classification("LABEL: legitimate\nINDICATORS: none").indicators == []
