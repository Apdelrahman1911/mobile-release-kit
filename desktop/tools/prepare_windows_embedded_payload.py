"""Offline projection of one reviewed Windows embedded CPython ZIP.

No acquisition, interpreter execution, installation, signature verification or
native qualification. The whole immutable ZIP must match the separately accepted
official HTTPS/release-checksum subject before any ZIP parsing or output. Missing
supplementary notices fail before output; no caller/environment can supply a pin.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import zipfile

_SPEC = importlib.util.spec_from_file_location(
    "_mrk_windows_runtime_preparation", Path(__file__).with_name("prepare_runtime.py")
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Fixed runtime preparer is unavailable")
runtime_preparation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(runtime_preparation)
PreparationError = runtime_preparation.PreparationError

TARGET = "x86_64-pc-windows-msvc"
PYTHON_VERSION = "3.14.7"
ZIP_NAME = "python-3.14.7-embed-amd64.zip"
ZIP_URL = "https://www.python.org/ftp/python/3.14.7/" + ZIP_NAME
ZIP_BYTES = 12673227
ZIP_SHA256 = "d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15"
OUTER_INVENTORY_SHA256 = "172b1201a41ba5d9b2d3fa605426a6cac9f12aeaf23616665e4c70bf8caa6000"
STDLIB_INVENTORY_SHA256 = "a36ba4a114629fb0d42a56f0449b5ce2f14381b8a2880d9fbe1ba6b77380fcc7"
CHUNK = 64 * 1024
NOTICE_SOURCE = "desktop/licenses/windows-embedded-runtime.txt"
NOTICE_NAME = "MRK-EMBEDDED-NOTICES.txt"
# Independently reviewed complete recipient text for the evidence-only profile.
# This pin is not recipient assent or binary-delivery/distribution approval.
# No placeholder/license label, command option, or environment opt-in is enough.
NOTICE_BYTES: int | None = 240822
NOTICE_SHA256: str | None = "6c814672403bec2064b22e54dbd028b055e0cacdc6837557a66cd5c0a04af360"
MAX_NOTICE_BYTES = 256 * 1024
GITHUB_CA_SOURCE = "desktop/cpython-source-inputs/github-ca.pem"
GITHUB_CA_BYTES = 240216
GITHUB_CA_SHA256 = "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f"
SOURCE_PROJECTION_NAME = "fullwalk-source"
UNDERPTH = (b"python314.zip\r\n.\r\n\r\n"
            b"# Uncomment to run site.main() automatically\r\n#import site\r\n")

# All 37 unmodified supplier members, including unused images/catalog. These pins
# come from accepted input04; precompiled stdlib is copied, never recompressed.
MEMBERS = (
    ("LICENSE.txt", 35407, "935cf13e19f8c31b497d20b05d73623431a226b230c3599bc30fa3348979bc68"),
    ("_asyncio.pyd", 78048, "f9594a2a4f45570dbfdf1f3471194ae7b27dc117c54b9af6bc22df9c93830f8b"),
    ("_bz2.pyd", 88288, "b938073c85cf6b9fe80556d7899ed1901e5e60b7adea2832442376239fb36b36"),
    ("_ctypes.pyd", 142560, "408cc4e7a22ffa418ca52f5e13fe9268a3c50a2bc9de02b0530b555ef591bc5a"),
    ("_decimal.pyd", 291552, "bc3a61685825ae37a4cd2b2b87fa27af12e01575c4f920788ea806e6781a2c79"),
    ("_elementtree.pyd", 138976, "d8a17f9c831e313b440e19e0d26e6c0e7ed830ff1f657887cbc26664d6ef4973"),
    ("_hashlib.pyd", 69344, "5933ef5eda7c0bca0b3874a6e2c5f13b91b8f2cfc29bc46160df3212a1dbee79"),
    ("_lzma.pyd", 160992, "d2abf8db7fb0cf6285663b177991691a41b37e215c3d71fd087a98d8ec1bee63"),
    ("_multiprocessing.pyd", 38624, "cea83c9bf3131d079c20066b626f67ab33021b476777be2d7be26d1fa5e4eb66"),
    ("_overlapped.pyd", 58080, "1d7028683e6ec50c159139238f90a6c8431ece139a4764900ca11c941ba05d46"),
    ("_queue.pyd", 36576, "2fd8668f52b34d0e71ae48784bd2e7d35e5d99df6f641edb0fc279235a187c8e"),
    ("_remote_debugging.pyd", 93408, "32b58c85e29ecc2378eddfe367745998fdb131e1ab6bb84d54e16f33806b584c"),
    ("_socket.pyd", 87776, "02265dd0d0287f3ffd287ea5d8e3c918a5a056e8ef2c4529857f5e84ec9e2519"),
    ("_sqlite3.pyd", 132832, "ec9694e5929747e93e05bc32427d24350dc4de5074b61a37bc961c3048794a67"),
    ("_ssl.pyd", 190688, "4cfb154c7cc525d57020c0e64f2dd876a78b46cd38419446392478de6b7b13b8"),
    ("_uuid.pyd", 28384, "fbfd7fe8583b346ba20b174b2510c0830237f5092bdf9fc26da9d6b25b018385"),
    ("_wmi.pyd", 40160, "b6fd41f079da0c0054829855360e88b8b762f5c42bb474c2fa02eae367839ad2"),
    ("_zoneinfo.pyd", 51936, "07469c7fc221663e423a2e6023a5b2ead3b10d0b40eb297887f4447a1ff1b2a3"),
    ("_zstd.pyd", 503520, "33c6eca99470c3eb9d776b617c550ad41b002a668336f062a9ab7be677a7409a"),
    ("libcrypto-3.dll", 6242552, "53c529145339fb042a3dcd3a09c2d7753204f8b4fc79d99e0d31e69a33985958"),
    ("libffi-8.dll", 39696, "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"),
    ("libssl-3.dll", 1329912, "b17a87979862d19241edc4318f967e24c3ec356ed6c2368f561179fab2311001"),
    ("libtommath.dll", 95456, "bf18448a56de62e56adb5a50040c08648f0bcf556217de90eca283490ee8c0c3"),
    ("pyexpat.pyd", 222944, "e34347c4e11b2ecc57df2ce1627ba7f98fd076e9df59951e9034f5aa8e95a2fc"),
    ("python.cat", 600973, "bd98c1a5acc6dc6850425221a755506571eac182cb0aa85f2f45a9a077a3c71b"),
    ("python.exe", 106208, "4942b86a6597e5aee0128daa00050ed79bc21f6e709a78eb19cbfeb0c2f39ac9"),
    ("python3.dll", 73952, "6c45910e7c82617ca6360820de861699cc99f9efee434df290aa4c6e38f39886"),
    ("python314._pth", 80, "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c"),
    ("python314.dll", 6785760, "0f9857ffdfe010fe6b99328d58c2e3c7472ce75f336bf9c2ad9bd5bca3bce700"),
    ("python314.zip", 4138882, "5a7a66daf1a2c2e3c8d7a4a0d095685ec301efc3ef28cc2419e3041bf5729b65"),
    ("pythonw.exe", 104672, "c197268f7e7cf2848b8c1ae59bbd0e0c14defe668a2d365302137ea929b47769"),
    ("select.pyd", 33504, "722328e7fad8048057fc966474ba73966d2ceebaa32e7344cce09640ab4dc9bd"),
    ("sqlite3.dll", 1584864, "d3e60dd22e62c9fbdb64b31b1b8c48782e1d4958d04d0bf830cffd31ace3275f"),
    ("unicodedata.pyd", 759008, "280b09bd97b598d18c0ed9542dc18ed35fa57a16e84f8e65fd9c6e96516c28d6"),
    ("vcruntime140.dll", 178616, "d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7"),
    ("vcruntime140_1.dll", 50112, "a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e"),
    ("winsound.pyd", 32992, "6a27340660de89d5da59445a77ac6b08d471e373304ce7294c198238f09f2dc2"),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def notice_bytes(source: Path) -> bytes:
    """An early closed gate, before creating even the runtime output directory."""
    require(type(NOTICE_BYTES) is int and 0 < NOTICE_BYTES <= MAX_NOTICE_BYTES
            and type(NOTICE_SHA256) is str
            and re.fullmatch(r"[0-9a-f]{64}", NOTICE_SHA256) is not None,
            "Windows exact recipient notice source is not admitted")
    source = runtime_preparation._root(source)
    path = source / NOTICE_SOURCE
    runtime_preparation._root(path.parent)
    data = runtime_preparation.read_checked(path, limit=MAX_NOTICE_BYTES)
    require(len(data) == NOTICE_BYTES and hashlib.sha256(data).hexdigest() == NOTICE_SHA256,
            "Windows supplementary notice bytes differ from the reviewed source pin")
    return data


def github_ca_bytes(source: Path) -> bytes:
    """The admitted controls leaf, never an ambient or logical-path fallback."""
    require(type(GITHUB_CA_BYTES) is int
            and 0 < GITHUB_CA_BYTES <= runtime_preparation.MAX_GITHUB_CA_BYTES
            and type(GITHUB_CA_SHA256) is str
            and re.fullmatch(r"[0-9a-f]{64}", GITHUB_CA_SHA256) is not None,
            "Windows fixed GitHub CA source is not admitted")
    path = runtime_preparation._root(source) / GITHUB_CA_SOURCE
    runtime_preparation._root(path.parent)
    data = runtime_preparation.read_checked(path, limit=runtime_preparation.MAX_GITHUB_CA_BYTES)
    require(len(data) == GITHUB_CA_BYTES and hashlib.sha256(data).hexdigest() == GITHUB_CA_SHA256,
            "Windows fixed GitHub CA bytes differ from the reviewed source pin")
    return data


def _source_payloads(source: Path, github_ca: bytes) -> list[tuple[str, bytes]]:
    """Snapshot only current core, six bootstraps and the separately pinned CA."""
    fixed_files = len(runtime_preparation.BOOTSTRAPS) + 1
    package = runtime_preparation._root(source / "src/mobile_release")
    # The full projection adds src/, src/mobile_release/, desktop/ and seven
    # desktop leaves to the core census. Reserve that overhead before output.
    candidates = runtime_preparation.files(package, reserve_entries=3 + fixed_files)
    require(candidates and len(candidates) + fixed_files <= runtime_preparation.MAX_FILES
            and all(path.suffix in {".py", ".json", ".pem"} for path in candidates),
            "Windows current core inventory differs from the preparation envelope")
    payloads: dict[str, bytes] = {}
    total = 0
    for path in candidates:
        content = runtime_preparation.read_checked(path, limit=runtime_preparation.MAX_CORE_BYTES - total)
        total += len(content)
        payloads["src/mobile_release/" + path.relative_to(package).as_posix()] = content
    desktop = runtime_preparation._root(source / "desktop")
    for name in runtime_preparation.BOOTSTRAPS:
        payloads["desktop/" + name] = runtime_preparation.read_checked(
            desktop / name, limit=runtime_preparation.MAX_BOOTSTRAP_BYTES)
    payloads["desktop/" + runtime_preparation.GITHUB_CA_NAME] = github_ca
    require(all(len(name) <= 512 and len(Path(name).parts) <= runtime_preparation.MAX_PATH_PARTS
                for name in payloads),
            "Windows projected source path exceeds the preparation envelope")
    return sorted(payloads.items())


def _write_source_projection(projection: Path, payloads: list[tuple[str, bytes]]) -> None:
    """Exclusive private data copy; never change or import the original checkout."""
    directories = {parent for name, _ in payloads for parent in Path(name).parents
                   if parent != Path(".")}
    projection.mkdir(mode=0o700)
    for relative in sorted(directories, key=lambda path: (len(path.parts), path.as_posix())):
        (projection / relative).mkdir(mode=0o700)
    for name, content in payloads:
        with (projection / name).open("xb") as output:
            require(output.write(content) == len(content), "Windows source projection copy was incomplete")
    expected = dict(payloads)
    actual = runtime_preparation.files(projection)
    require([path.relative_to(projection).as_posix() for path in actual] == list(expected),
            "Windows source projection gained, lost or aliased a member")
    for path in actual:
        content = expected[path.relative_to(projection).as_posix()]
        require(runtime_preparation.read_checked(path, limit=len(content)) == content,
                "Windows projected source bytes changed")


def archive_bytes(archive: Path) -> bytes:
    require(archive.is_absolute() and ".." not in archive.parts and archive.name == ZIP_NAME,
            "The fixed Windows archive must have its explicit absolute pathname")
    runtime_preparation._root(archive.parent)
    data = runtime_preparation.read_checked(archive, limit=ZIP_BYTES)
    require(len(data) == ZIP_BYTES and hashlib.sha256(data).hexdigest() == ZIP_SHA256,
            "The exact reviewed Windows whole-ZIP bytes are unavailable")
    return data


def member_roster(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Only the exact fixed supplier format; not an arbitrary ZIP extractor."""
    members = archive.infolist()
    require(len(members) == len(MEMBERS) and archive.comment == b"",
            "Windows supplier archive member count or comment differs")
    expected = {name: size for name, size, _ in MEMBERS}
    require(len(expected) == len(MEMBERS)
            and {item.filename for item in members} == set(expected)
            and len({item.filename.casefold() for item in members}) == len(MEMBERS),
            "Windows supplier archive gained, lost or aliased a member")
    for item in members:
        require(item.filename == item.orig_filename
                and runtime_preparation._safe_name(item.filename)
                and item.file_size == expected[item.filename]
                and not item.is_dir()
                and stat.S_ISREG(item.external_attr >> 16)
                and item.create_system == 0 and item.create_version == 20
                and item.extract_version == 20 and item.flag_bits == 0
                and item.compress_type == zipfile.ZIP_DEFLATED
                and not item.extra and not item.comment,
                "A fixed Windows supplier member has unexpected metadata")
    return sorted(members, key=lambda item: item.filename)


def check_supplier_copy(python: Path, notices: bytes) -> None:
    expected = {name: (size, digest) for name, size, digest in MEMBERS}
    expected[NOTICE_NAME] = (len(notices), hashlib.sha256(notices).hexdigest())
    actual = runtime_preparation.files(python)
    require([path.name for path in actual] == sorted(expected)
            and all(path.parent == python for path in actual),
            "Windows Python payload has an extra startup file or member")
    for path in actual:
        size, digest = expected[path.name]
        data = runtime_preparation.read_checked(path, limit=size)
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
                "Windows copied supplier or notice bytes changed")
        if path.name == "python314._pth":
            require(data == UNDERPTH, "Windows isolated startup policy changed")


def prepare(source: Path, archive: Path, runtime: Path) -> dict[str, str]:
    # Notice rejection and complete immutable input admission happen BEFORE any
    # output. Do not reopen the archive pathname after hashing. Input04 already
    # bounded both ZIP layers/headers/ZIP64/overlaps; the complete digest fixes
    # those exact bytes, while the closed roster and each streamed CRC/hash below
    # still check this copy. No generic archive proof/decoder is introduced.
    notices = notice_bytes(source)
    github_ca = github_ca_bytes(source)
    data = archive_bytes(archive)
    require(runtime.is_absolute() and ".." not in runtime.parts
            and runtime_preparation._safe_name(runtime.name),
            "Windows runtime output must have an explicit absolute ordinary name")
    runtime_preparation._root(runtime.parent)
    projection = runtime.parent / SOURCE_PROJECTION_NAME
    require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
                for left, right in ((source, runtime), (source, projection), (runtime, projection))),
            "Windows source and preparation outputs must be disjoint")
    for destination in (runtime, projection):
        try:
            destination.lstat()
        except FileNotFoundError:
            continue
        raise PreparationError("Windows preparation never merges or replaces an existing output")
    payloads = _source_payloads(source, github_ca)
    with io.BytesIO(data) as original, zipfile.ZipFile(original, "r", allowZip64=False) as supplier:
        entries = member_roster(supplier)
        pins = {name: (size, digest) for name, size, digest in MEMBERS}
        _write_source_projection(projection, payloads)
        runtime.mkdir(mode=0o700)
        python = runtime / "python"
        python.mkdir(mode=0o700)
        for item in entries:
            size, expected = pins[item.filename]
            digest, total = hashlib.sha256(), 0
            with supplier.open(item, "r") as incoming, (python / item.filename).open("xb") as output:
                while True:
                    chunk = incoming.read(min(CHUNK, size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= size, "Windows supplier member exceeded its admitted size")
                    digest.update(chunk)
                    require(output.write(chunk) == len(chunk), "Windows member copy was incomplete")
            require(total == size and digest.hexdigest() == expected,
                    "Windows supplier member failed complete size/CRC/hash correspondence")
        with (python / NOTICE_NAME).open("xb") as output:
            require(output.write(notices) == len(notices), "Windows notice copy was incomplete")
        check_supplier_copy(python, notices)
    prepared = runtime_preparation.prepare(projection, runtime, TARGET)
    # These are preparation bindings, not a new execution/provenance grant. The
    # existing CI receipt adds source/run/attempt and original native observations.
    return {**prepared, "inputSha256": ZIP_SHA256,
            "supplierInventorySha256": OUTER_INVENTORY_SHA256,
            "stdlibInventorySha256": STDLIB_INVENTORY_SHA256,
            "noticeSha256": hashlib.sha256(notices).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.source, args.archive, args.runtime_root), sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile):
        parser.exit(1, "Windows preparation refused. Inputs and any partial output were preserved; no runtime was executed or qualified.\n")


if __name__ == "__main__":
    main()
