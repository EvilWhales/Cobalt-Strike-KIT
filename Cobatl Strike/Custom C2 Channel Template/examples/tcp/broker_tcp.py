import argparse
import base64
import http.client
import json
import logging
import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# These are all set from CLI args in main()
CLI_HOST: Optional[str] = None      # outbound HTTP(S) host (from --host)
CLI_PORT: Optional[int] = None      # outbound HTTP(S) port (from --port)
LISTEN_HOST: Optional[str] = None   # local TCP listen host (from --listen-host)
LISTEN_PORT: Optional[int] = None   # local TCP listen port (from --listen-port)


# ---------------------------------------------------------------------------
# Core HTTP bridge logic (decode → parse → send HTTP → encode)
# ---------------------------------------------------------------------------

def decode_request(encoded_request: str) -> Dict[str, Any]:
    """
    Decode the base64-encoded JSON request into a Python dictionary.
    """
    logging.debug("Decoding incoming request (length: %d).", len(encoded_request))
    decoded_bytes = base64.b64decode(encoded_request)
    decoded_str = decoded_bytes.decode("utf-8")
    logging.debug("Decoded request JSON: %s", decoded_str)
    return json.loads(decoded_str)


def build_headers(header_lines: Optional[List[str]]) -> Dict[str, str]:
    """
    Build a headers dictionary from a list of 'Name: Value' strings.
    """
    headers: Dict[str, str] = {}
    if not header_lines:
        logging.debug("No headers provided in request.")
        return headers

    for line in header_lines:
        if not line:
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            value = value.strip()
            headers[name] = value
            logging.debug("Parsed header: %s: %s", name, value)
        else:
            logging.warning("Skipping malformed header line (no colon found): %r", line)

    logging.info("Built %d request headers.", len(headers))
    return headers


def send_http_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send an HTTP/HTTPS request based on the decoded request dictionary.
    Uses CLI_HOST / CLI_PORT for the destination.
    """
    scheme = request.get("scheme", "http")
    host = CLI_HOST
    port = CLI_PORT
    path = request.get("path", "/")
    method = request.get("method", "GET")
    headers = build_headers(request.get("headers"))
    body_b64 = request.get("body", "")
    body = base64.b64decode(body_b64) if body_b64 else None

    if not host:
        raise ValueError("Destination host (--host) is required.")
    if port is None:
        raise ValueError("Destination port (--port) is required.")

    logging.info(
        "Preparing %s request to %s://%s:%s%s",
        method,
        scheme,
        host,
        port,
        path,
    )
    logging.debug("Request headers: %r", headers)
    if body is not None:
        logging.info("Request has a body (%d bytes).", len(body))

    connection_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection

    if scheme == "https":
        logging.debug("Creating HTTPS connection with unverified SSL context.")
        conn = connection_cls(host, port, context=ssl._create_unverified_context(), timeout=10)
    else:
        logging.debug("Creating HTTP connection.")
        conn = connection_cls(host, port, timeout=10)

    try:
        conn.request(method, path, body=body, headers=headers)
        logging.info("Request sent, awaiting response...")
        resp = conn.getresponse()
        resp_body = resp.read()
        logging.info(
            "Received response: %s %s (%d bytes).",
            resp.status,
            resp.reason,
            len(resp_body),
        )
        resp_headers_list = [f"{k}: {v}" for k, v in resp.getheaders()]
        logging.debug("Response headers: %r", resp_headers_list)
    finally:
        conn.close()
        logging.debug("Connection to %s:%s closed.", host, port)

    return {
        "status_code": resp.status,
        "status_text": resp.reason,
        "headers": resp_headers_list,
        "body": base64.b64encode(resp_body).decode("ascii"),
    }


def encode_response(response_obj: Dict[str, Any]) -> str:
    """
    Encode a response dictionary as base64-encoded JSON.
    """
    json_bytes = json.dumps(response_obj).encode("utf-8")
    logging.debug("Encoding response JSON (%d bytes) to base64.", len(json_bytes))
    return base64.b64encode(json_bytes).decode("ascii")


def process_encoded_request(encoded_request: str) -> str:
    """
    High-level core processing function.

    Takes raw encoded request data and returns raw encoded response data.

    Steps:
      1. Decode base64 → JSON → dict
      2. Perform HTTP/HTTPS request based on dict
      3. Encode response dict → JSON → base64
    """
    logging.info("Processing encoded request (length: %d).", len(encoded_request))
    request_obj = decode_request(encoded_request)
    logging.debug("Decoded request object: %r", request_obj)

    response_obj = send_http_request(request_obj)
    encoded_response = encode_response(response_obj)
    logging.info("Encoded response (length: %d).", len(encoded_response))

    return encoded_response


# ---------------------------------------------------------------------------
# handle a callback
#
# This function is what you modify!
#
# ---------------------------------------------------------------------------

def handleCallback(process_func: Callable[[str], str] = process_encoded_request) -> bool:
    """
    Handle a single callback cycle over a TCP connection.

    Listens on LISTEN_HOST:LISTEN_PORT for one client, exchanges a length-prefixed
    request/response pair, and returns.
    """

    if LISTEN_HOST is None or LISTEN_PORT is None:
        raise RuntimeError("LISTEN_HOST and LISTEN_PORT must be set before calling handleCallback().")

    def _read_exact(conn: socket.socket, num_bytes: int) -> bytes:
        data = b""
        while len(data) < num_bytes:
            chunk = conn.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Socket closed while reading data")
            data += chunk
        return data

    def _read_length_prefixed(conn: socket.socket) -> bytes:
        raw_len = _read_exact(conn, 4)
        msg_len = int.from_bytes(raw_len, byteorder="little")
        if msg_len == 0:
            raise ValueError("Received empty message")
        return _read_exact(conn, msg_len)

    def _write_length_prefixed(conn: socket.socket, payload: bytes) -> None:
        conn.sendall(len(payload).to_bytes(4, byteorder="little"))
        if payload:
            conn.sendall(payload)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((LISTEN_HOST, LISTEN_PORT))
            server.listen(1)
            server.settimeout(1.0)

            logging.info("Listening for callbacks on %s:%s", LISTEN_HOST, LISTEN_PORT)

            try:
                conn, addr = server.accept()
            except socket.timeout:
                return False

            with conn:
                logging.info("Accepted connection from %s:%s", addr[0], addr[1])
                raw_request = _read_length_prefixed(conn)
                encoded_request = raw_request.decode("utf-8")

                encoded_response = process_func(encoded_request)
                _write_length_prefixed(conn, encoded_response.encode("utf-8"))
                logging.info("Sent response over TCP (%d bytes).", len(encoded_response))

        return True

    except Exception as exc:  # noqa: BLE001
        logging.exception("Error in handleCallback: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point. Repeatedly calls handleCallback to process requests.
    """
    global CLI_HOST, CLI_PORT, LISTEN_HOST, LISTEN_PORT

    parser = argparse.ArgumentParser(description="HTTP bridge broker.")
    parser.add_argument(
        "--host",
        dest="host",
        required=True,
        help="Destination host for outgoing HTTP/HTTPS requests (required).",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        required=True,
        help="Destination port for outgoing HTTP/HTTPS requests (required).",
    )
    parser.add_argument(
        "--listen-host",
        dest="listen_host",
        required=True,
        help="Host/interface to listen on for incoming TCP callbacks (e.g. 0.0.0.0).",
    )
    parser.add_argument(
        "--listen-port",
        dest="listen_port",
        type=int,
        required=True,
        help="Port to listen on for incoming TCP callbacks.",
    )

    args = parser.parse_args()

    CLI_HOST = args.host
    CLI_PORT = args.port
    LISTEN_HOST = args.listen_host
    LISTEN_PORT = args.listen_port

    logging.info("Destination (teamserver) host: %s", CLI_HOST)
    logging.info("Destination (teamserver) port: %s", CLI_PORT)
    logging.info("Listening on %s:%s for callbacks.", LISTEN_HOST, LISTEN_PORT)

    while True:
        handled = handleCallback(process_encoded_request)



if __name__ == "__main__":
    main()

