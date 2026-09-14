import requests


def poll(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str) -> dict:
    """Retrieve pending activations and the current owner-signed calendar
    (OpenADR pull model). Returns the full poll body:
    {"activations": [...], "calendar": <compact JWS or None>}.

    The appliance always initiates: an outbound connection traverses the home
    router without any inbound connectivity, and the TLS handshake proves to
    the appliance that it is really talking to the VPP.
    """
    r = requests.get(f"{vpp_mtls_url}/openadr/poll",
                     cert=(ven_cert, ven_key), verify=ca_file)
    r.raise_for_status()
    return r.json()


def submit_evidence(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str,
                    jws: str) -> dict:
    """Send signed participation evidence to the VPP (outbound, as always)."""
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
        "applianceProfile": profile,  # (P, max, rec) the VEN reports to the VTN
    }
    r = requests.post(
        f"{vpp_mtls_url}/openadr/register",
        json=body,
        cert=(ven_cert, ven_key),  # mutual TLS: the VEN presents its certificate
        verify=ca_file,
    )
    r.raise_for_status()
    return r.json()
