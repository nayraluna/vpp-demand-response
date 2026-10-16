import http.client
import json
import ssl
from urllib.parse import urlparse

import requests
from cryptography import x509


def poll(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str) -> tuple[int, dict, x509.Certificate]:
    """OpenADR pull: the appliance always initiates, so the home router needs no inbound port.

    Returns the status, the body, and the certificate the VTN presented on this very connection,
    read right after the handshake, so the appliance judges the channel that delivered the data.
    """
    url = urlparse(vpp_mtls_url)
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(ven_cert, ven_key)
    conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=15)
    try:
        conn.connect()
        peer = x509.load_der_x509_certificate(conn.sock.getpeercert(binary_form=True))
        conn.request("GET", "/openadr/poll", headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = json.loads(response.read() or b"{}")
        return response.status, body, peer
    finally:
        conn.close()


def submit_evidence(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str,
                    jws: str) -> dict:
    r = requests.post(f"{vpp_mtls_url}/evidence", json={"evidence": jws},
                      cert=(ven_cert, ven_key), verify=ca_file)
    return {"status_code": r.status_code, "body": r.json()}


def register(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str,
             ven_name: str, profile: dict) -> dict:
    body = {
        "oadrProfileName": "2.0b",
        "oadrTransportName": "simpleHttp",
        "oadrReportOnly": False,
        "venName": ven_name,
        "applianceProfile": profile,
    }
    r = requests.post(
        f"{vpp_mtls_url}/openadr/register",
        json=body,
        cert=(ven_cert, ven_key),
        verify=ca_file,
    )
    r.raise_for_status()
    return r.json()
