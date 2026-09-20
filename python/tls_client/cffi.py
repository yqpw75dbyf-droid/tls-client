"""Loads the tls-client shared library and exposes its C functions.

The Go core in ../../cffi_dist is compiled to a C shared library that exports
six functions (request, getCookiesFromSession, addCookiesToSession,
destroySession, destroyAll, freeMemory). This module finds that library and
wires each function up through ctypes.

The library is not shipped in this package because building it needs cgo and a
C toolchain. Point the loader at it in one of three ways, tried in order:

1. the TLS_CLIENT_LIBRARY environment variable, set to the full file path;
2. a file dropped into this package's ``dependencies`` directory;
3. a file in the current working directory.

Build it once from the repo root with:

    cd cffi_dist && CGO_ENABLED=1 go build -buildmode=c-shared \\
        -o dist/tls-client.so .          # .dll on Windows, .dylib on macOS
"""

import ctypes
import glob
import os
import platform

_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dependencies")


def _platform_extension() -> str:
    system = platform.system()
    if system == "Windows":
        return ".dll"
    if system == "Darwin":
        return ".dylib"
    return ".so"


def _candidate_paths() -> list:
    """Every place a shared library might live, most specific first."""
    paths = []

    env = os.environ.get("TLS_CLIENT_LIBRARY")
    if env:
        paths.append(env)

    ext = _platform_extension()
    machine = platform.machine().lower()
    # amd64 and x86_64 name the same architecture; match either in filenames.
    arch_aliases = {"amd64", "x86_64"} if machine in {"amd64", "x86_64"} else {machine}

    for directory in (_LIB_DIR, os.getcwd()):
        matches = sorted(glob.glob(os.path.join(directory, "*" + ext)))
        # Prefer a file whose name mentions this architecture, but fall back to
        # any library with the right extension so a single-arch build just works.
        arch_matches = [m for m in matches if any(a in m.lower() for a in arch_aliases)]
        paths.extend(arch_matches or matches)

    return paths


def _load_library() -> ctypes.CDLL:
    tried = _candidate_paths()
    for path in tried:
        if path and os.path.isfile(path):
            return ctypes.cdll.LoadLibrary(path)

    ext = _platform_extension()
    raise FileNotFoundError(
        "tls-client shared library not found. Build it with\n"
        "    cd cffi_dist && CGO_ENABLED=1 go build -buildmode=c-shared "
        f"-o dist/tls-client{ext} .\n"
        f"then set TLS_CLIENT_LIBRARY to its path or drop it in {_LIB_DIR}.\n"
        f"Looked in: {tried or '(nowhere: no candidates)'}"
    )


library = _load_library()

request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

get_cookies_from_session = library.getCookiesFromSession
get_cookies_from_session.argtypes = [ctypes.c_char_p]
get_cookies_from_session.restype = ctypes.c_char_p

add_cookies_to_session = library.addCookiesToSession
add_cookies_to_session.argtypes = [ctypes.c_char_p]
add_cookies_to_session.restype = ctypes.c_char_p

destroy_session = library.destroySession
destroy_session.argtypes = [ctypes.c_char_p]
destroy_session.restype = ctypes.c_char_p

destroy_all = library.destroyAll
destroy_all.restype = ctypes.c_char_p

# freeMemory takes the response id and releases the C string the Go side kept
# alive for it. Every call that reads a returned string must free it after.
free_memory = library.freeMemory
free_memory.argtypes = [ctypes.c_char_p]
free_memory.restype = None
