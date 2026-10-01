"""Dedicated fixed main-thread edit bootstrap. No project imports or fallback."""
import os
import sys
import time

# The originals survive removal of BOTH sys alias sets and actual close. They
# are never detached, abandoned to GC, or replaced by a second stdio owner.
_IMAGE_STDIO_ORIGINALS = None
_IMAGE_STDIO_CONTEXT = None


def _capture_image_stdio():
    import _io
    import msvcrt
    global _IMAGE_STDIO_ORIGINALS
    if _IMAGE_STDIO_ORIGINALS is not None:
        raise RuntimeError("Original image standard streams cannot be recaptured")
    values = []
    for number, (name, original_name) in enumerate((("stdin", "__stdin__"), ("stdout", "__stdout__"), ("stderr", "__stderr__"))):
        text = getattr(sys, name)
        if type(text) is not _io.TextIOWrapper or text is not getattr(sys, original_name):
            raise RuntimeError("Supplier standard stream is not representable")
        buffered, raw = text.buffer, text.buffer.raw
        expected = _io.BufferedReader if number == 0 else _io.BufferedWriter
        if (type(buffered) is not expected or type(raw) is not _io.FileIO or raw.closefd is not False
                or text.closed or buffered.closed or raw.closed or raw.fileno() != number):
            raise RuntimeError("Supplier standard stream is not admitted")
        values.append((text, buffered, raw))
    mappings = tuple(msvcrt.get_osfhandle(n) for n in range(3))
    _IMAGE_STDIO_ORIGINALS = tuple(values)  # Root BEFORE alias retirement/imports.
    for name in ("stdin", "stdout", "stderr", "__stdin__", "__stdout__", "__stderr__"):
        setattr(sys, name, None)
    return _IMAGE_STDIO_ORIGINALS, mappings


def main() -> int:
    global _IMAGE_STDIO_CONTEXT
    started = time.monotonic()
    domain = "configuration" if len(sys.argv) == 2 else sys.argv[2] if len(sys.argv) == 3 else None
    windows_images = sys.platform == "win32" and domain == "metadata_images"
    windows_notes = sys.platform == "win32" and domain == "required_notes"
    if (domain not in {"configuration", "github_workflows", "metadata_text", "required_notes", "release_version", "metadata_images"}
            or len(sys.argv) == 3 and domain == "configuration"
            or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or not os.path.isabs(sys.argv[1])
            or sys.version_info < (3, 11) or not (sys.platform.startswith("linux") or sys.platform == "darwin" or windows_images or windows_notes)
            or (domain in {"github_workflows", "metadata_text", "release_version", "metadata_images"} and sys.platform != "linux" and not windows_images)):
        return 78
    originals = mappings = None
    if windows_images or windows_notes:
        originals, mappings = _capture_image_stdio()  # Before core imports or protocol IO.
    sys.path.insert(0, sys.argv[1])
    if windows_images:
        from mobile_release._desktop_image_writer_windows import _bootstrap_image_stdio
        _IMAGE_STDIO_CONTEXT = _bootstrap_image_stdio(started=started, originals=originals, mappings=mappings)
    elif windows_notes:
        from mobile_release._desktop_image_writer_windows import _bootstrap_notes_stdio
        _IMAGE_STDIO_CONTEXT = _bootstrap_notes_stdio(started=started, originals=originals, mappings=mappings)
    from mobile_release._desktop_edit_engine import main as run_engine
    if windows_images:
        return run_engine(started=started, domain=domain, _image_stdio=_IMAGE_STDIO_CONTEXT)
    if windows_notes:
        return run_engine(started=started, domain=domain, _notes_stdio=_IMAGE_STDIO_CONTEXT)
    return run_engine(started=started, domain=domain)


if __name__ == "__main__":
    try:
        code = main()
    except BaseException:
        code = 78  # No traceback, private file content, argv or native path.
    raise SystemExit(code)
