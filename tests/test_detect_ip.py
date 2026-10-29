from zenlens.detect import detect
from zenlens.gate import Blocked, egress_check
from zenlens.sanitize import redact

import pytest


def hits(t):
    return [(t[s.start:s.end], s.kind) for s in detect(t)]


@pytest.mark.parametrize("text,ip", [
    ("db at 192.168.1.20:5432", "192.168.1.20"), ("host 10.0.12.34.", "10.0.12.34"),
    ("GET https://172.16.5.4/api", "172.16.5.4"), ("gw 255.255.255.0", "255.255.255.0"), ("server 10.1.2.3", "10.1.2.3"), ("rebuild 10.9.8.7", "10.9.8.7"),
    ("v6 2001:db8::8a2e:370:7334 up", "2001:db8::8a2e:370:7334"), ("gw fd00:1234:5678::25", "fd00:1234:5678::25"),
])
def test_ip_found(text, ip):
    assert (ip, "IP") in hits(text)


@pytest.mark.parametrize("text", [
    "version 1.2.3", "v1.2.3.4", "release 1.2.3.4.5", "date 29.10.2026", "bad 999.1.1.1", "256.1.1.1",
    "time 12:30:45", "mac aa:bb:cc:dd:ee:ff", "std::vector", "a::b", "price 1,499.00", "build 2026.10.29",
    "version 2.10.0.1 released", "Release 4.0.0.1", "build 1.0.0.12",
])
def test_ip_negatives(text):
    assert not any(k == "IP" for _, k in hits(text))


def test_ip_does_not_steal_phone_or_card():
    t = "call +91 9876543210 card 4111 1111 1111 1111 from 8.8.8.8"
    assert hits(t) == [("+91 9876543210", "PHONE"), ("4111 1111 1111 1111", "CARD"), ("8.8.8.8", "IP")]


def test_ip_redacted_and_gated():
    clean, _ = redact("ssh admin@10.1.2.3")
    assert "10.1.2.3" not in clean
    with pytest.raises(Blocked):
        egress_check("server 10.1.2.3")
