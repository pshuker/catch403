"""
Burpee — parses Burp Suite saved request files.

A Burp request file looks like:
    POST /path HTTP/1.1
    Host: example.com
    Content-Type: application/x-www-form-urlencoded

    param1=value1&param2=value2

parse_request(path)          -> (headers_dict, post_body_str)
get_method_and_resource(path) -> (method_str, resource_str)
"""


def _read(path: str) -> list[str]:
    with open(path, "r", errors="replace") as f:
        return f.read().splitlines()


def parse_request(path: str) -> tuple[dict, str]:
    """Return (headers_dict, post_body).  Body is '' for GET requests."""
    lines = _read(path)
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for i, line in enumerate(lines):
        if i == 0:
            continue  # skip request line — handled by get_method_and_resource
        if not in_body:
            if line.strip() == "":
                in_body = True
            else:
                if ":" in line:
                    key, _, val = line.partition(":")
                    headers[key.strip()] = val.strip()
        else:
            body_lines.append(line)

    return headers, "\n".join(body_lines)


def get_method_and_resource(path: str) -> tuple[str, str]:
    """Return (METHOD, /resource/path) from the first line of the request."""
    lines = _read(path)
    if not lines:
        return ("GET", "/")
    parts = lines[0].split()
    method   = parts[0].upper() if len(parts) > 0 else "GET"
    resource = parts[1]         if len(parts) > 1 else "/"
    return method, resource
