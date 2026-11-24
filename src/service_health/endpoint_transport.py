"""Perform one anonymous endpoint GET in a deadline-limited worker process."""

import sys
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ENDPOINT_LIMIT = 65536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_endpoint(url):
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(url, headers={"Accept": "application/json"})
    with opener.open(request, timeout=5) as response:
        body = response.read(ENDPOINT_LIMIT + 1)
        if len(body) <= ENDPOINT_LIMIT and response.length:
            raise IncompleteRead(body, response.length)
        return body


def main():
    try:
        body = read_endpoint(sys.stdin.buffer.read().decode("ascii"))
    except HTTPError as error:
        error.close()
        sys.stdout.write(str(error.code))
        return 1
    except (HTTPException, OSError, ValueError):
        return 2
    sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
