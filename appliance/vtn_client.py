import requests


def poll(vpp_mtls_url: str, ca_file: str, ven_cert: str, ven_key: str) -> dict:
    """OpenADR pull: the appliance always initiates, so the home router needs no inbound port."""
    r = requests.get(f"{vpp_mtls_url}/openadr/poll",
                     cert=(ven_cert, ven_key), verify=ca_file)
    r.raise_for_status()
    return r.json()


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
