"""Serve an ASGI app over TLS 1.3 only. uvicorn has no option for a minimum TLS version.

    python ../serve_tls.py app.main:app 8081 ../certs/server.crt ../certs/server.key
"""
import os
import ssl
import sys

import uvicorn


def main() -> None:
    app, port, certfile, keyfile = sys.argv[1:5]
    sys.path.insert(0, os.getcwd())  # the app package sits in the working directory, as with uvicorn's CLI
    config = uvicorn.Config(app, host="0.0.0.0", port=int(port),
                            ssl_certfile=certfile, ssl_keyfile=keyfile)
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
