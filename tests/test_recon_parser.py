from pathlib import Path

from recon_ai.parser import parse_nmap_text, parse_nmap_xml

SAMPLE = Path(__file__).resolve().parent.parent / "recon_ai" / "samples" / "sample_nmap.xml"


def test_xml_hosts_and_ports():
    data = parse_nmap_xml(str(SAMPLE))
    assert data.hosts
    host = data.hosts[0]
    assert host.hostname == "lab-target.local"
    ports = {p.number: p for p in host.ports}
    assert ports[21].service == "ftp"
    assert ports[22].service == "ssh"
    assert "vsftpd" in ports[21].version or "vsftpd" in ports[21].service


def test_text_parser_reads_open_ports():
    text = (
        "Nmap scan report for 10.0.0.5\n"
        "Host is up (0.001s latency).\n"
        "PORT   STATE SERVICE VERSION\n"
        "22/tcp open  ssh     OpenSSH 7.2p2\n"
        "80/tcp open  http    Apache httpd 2.4.29\n"
    )
    data = parse_nmap_text(text)
    assert data.hosts[0].ip == "10.0.0.5"
    assert {p.number for p in data.hosts[0].ports} == {22, 80}


def test_text_parser_empty_input():
    assert parse_nmap_text("").hosts == []
