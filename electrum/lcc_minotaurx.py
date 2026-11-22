"""Native Litecoin Cash MinotaurX hash interface.

The cryptographic implementation is based on Litecoin Cash Core.

This interface does not use RPC, Docker or a running Core node.
"""

import ctypes
import sys
from pathlib import Path


class MinotaurXError(Exception):
    pass


def _library_filename():
    if sys.platform == "win32":
        return "lcc_minotaurx.dll"
    if sys.platform == "darwin":
        return "liblcc_minotaurx.dylib"
    return "liblcc_minotaurx.so"


def _load_library():
    electrum_dir = Path(__file__).resolve().parent
    filename = _library_filename()

    candidates = [
        electrum_dir / filename,
        electrum_dir.parent / "native" / "minotaurx" / "build" / filename,
    ]

    path = next((p for p in candidates if p.is_file()), candidates[0])

    if not path.is_file():
        raise MinotaurXError(
            f"Native MinotaurX library not found: {path}"
        )

    try:
        library = ctypes.CDLL(str(path))
    except OSError as exc:
        raise MinotaurXError(
            f"Unable to load MinotaurX library: {exc}"
        ) from exc

    library.lcc_minotaurx_hash.argtypes = (
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte),
    )

    library.lcc_minotaurx_hash.restype = ctypes.c_int

    return library


def minotaurx_hash(data: bytes) -> bytes:
    """Return the 32-byte native MinotaurX hash."""
    if not isinstance(data, bytes) or not data:
        raise MinotaurXError("Expected non-empty bytes")

    library = _load_library()

    input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    output_buffer = (ctypes.c_ubyte * 32)()

    result = library.lcc_minotaurx_hash(
        input_buffer,
        len(data),
        output_buffer,
    )

    if result != 0:
        raise MinotaurXError("Native MinotaurX calculation failed")

    return bytes(output_buffer)


def minotaur_hash(data: bytes) -> bytes:
    """Return classical Minotaur hash in Core internal byte order."""
    if not isinstance(data, bytes) or not data:
        raise MinotaurXError("Expected non-empty bytes")

    library = _load_library()

    library.lcc_minotaur_hash.argtypes = (
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte),
    )
    library.lcc_minotaur_hash.restype = ctypes.c_int

    input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    output_buffer = (ctypes.c_ubyte * 32)()

    result = library.lcc_minotaur_hash(
        input_buffer,
        len(data),
        output_buffer,
    )

    if result != 0:
        raise MinotaurXError("Native classical Minotaur failed")

    return bytes(output_buffer)
