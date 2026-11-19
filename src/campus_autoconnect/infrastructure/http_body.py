"""Read a bounded HTTP response without automatic decompression."""

import time
import zlib

import httpx


class BodyReadError(ValueError):
    pass


def read_bounded_body(response: httpx.Response, limit: int, *, seconds: float = 6) -> bytes:
    encoding = response.headers.get("content-encoding", "identity").lower()
    if encoding not in {"identity", "gzip"}:
        raise BodyReadError("unsupported_page_encoding")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    content = bytearray()
    wire_bytes = 0
    started = time.monotonic()
    try:
        for raw in response.iter_raw():
            wire_bytes += len(raw)
            if wire_bytes > limit:
                raise BodyReadError("page_transfer_limit")
            if time.monotonic() - started > seconds:
                raise BodyReadError("page_read_timeout")
            chunk = decoder.decompress(raw, limit - len(content) + 1) if decoder else raw
            if len(content) + len(chunk) > limit:
                raise BodyReadError("page_size_limit")
            content.extend(chunk)
    except zlib.error as exc:
        raise BodyReadError("invalid_compressed_page") from exc
    if decoder and (not decoder.eof or decoder.unused_data):
        raise BodyReadError("invalid_compressed_page")
    return bytes(content)
