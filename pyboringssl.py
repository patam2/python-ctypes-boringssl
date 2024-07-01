from bsslrequests import BoringSSLBackend
import httpcore


def log(event_name, info):
    print(event_name, info) 

with httpcore.ConnectionPool(network_backend=BoringSSLBackend()) as http:
    resp = http.request(
        'GET', 
        'https://tls.browserleaks.com/tls',
        extensions={"trace": log}
    )

print(resp.content)