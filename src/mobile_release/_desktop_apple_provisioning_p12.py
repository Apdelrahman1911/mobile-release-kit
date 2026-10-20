"""One fixed P12 extraction on the existing Apple saved-command operation.

The private input is borrowed from that operation's original material reader.
The bundled Ruby helper receives only two finite scratch paths. Its bounded
PUBLIC DER output is not a CertificateBinding, trust verdict or key exporter.
"""
from __future__ import annotations

import hashlib
import re
import struct

from .apple_provisioning_api import ProvisioningError
from .build_inputs import FiniteScratch, finite_scratch
from .owned_process import PRIVATE_OUTPUT_LIMIT, run_owned


P12_LIMIT = 4 * 1024 * 1024
PASSWORD_LIMIT = 4096
P8_LIMIT = 16 * 1024
CERTIFICATE_LIMIT = 64 * 1024
SPKI_LIMIT = 16 * 1024
CHAIN_LIMIT = 8
MAGIC = b"MRK-P12-PUBLIC/1\n"
HEADER = struct.Struct(">IIB")
OUTPUT_LIMIT = len(MAGIC) + HEADER.size + CERTIFICATE_LIMIT + SPKI_LIMIT + CHAIN_LIMIT * (4 + CERTIFICATE_LIMIT)
MODES = frozenset(("profile-review", "profile-reuse", "profile-create", "profile-reconcile", "p12-review", "p12-reuse"))
LAYOUT = "apple-provisioning-p12"


def _need(condition, code="p12_extraction_refused"):
    if not condition:
        raise ProvisioningError(code)


def _expected(value):
    _need(type(value) is str and len(value) in (64, 95), "p12_expected_certificate_required")
    _need(bool(re.fullmatch(r"[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}", value)),
          "p12_expected_certificate_required")
    return value.replace(":", "").lower()


def _selected_expected(operation):
    if operation.request.context["mode"] in {"p12-review", "p12-reuse"}:
        # Comparison from the SAME native bound record, not a renderer hash or
        # permission to rewrite the saved project's expected signer.
        return _expected(operation.request.native["p12"]["expectedCertificateSha256"])
    return _expected(operation.config.section("ios").get("distributionCertificateSha256"))


def _material(value):
    _need(type(value) is tuple and len(value) == 5 and all(type(part) is bytes for part in value))
    _need(0 < len(value[0]) <= P8_LIMIT and len(value[1]) == 10 and len(value[2]) == 36)
    _need(0 < len(value[3]) <= P12_LIMIT, "p12_automation_size_unsupported")
    _need(0 < len(value[4]) <= PASSWORD_LIMIT and b"\0" not in value[4])
    try:
        value[4].decode("utf-8")
    except UnicodeError:
        raise ProvisioningError("p12_extraction_refused") from None
    return value


def parse_public_frame(raw, expected):
    """Closed bounded DATA decoder; DER/authenticity is validated downstream."""
    expected = _expected(expected)
    _need(type(raw) is bytes and len(MAGIC) + HEADER.size < len(raw) <= OUTPUT_LIMIT)
    _need(raw.startswith(MAGIC))
    leaf_length, spki_length, count = HEADER.unpack_from(raw, len(MAGIC))
    _need(0 < leaf_length <= CERTIFICATE_LIMIT and 0 < spki_length <= SPKI_LIMIT and count <= CHAIN_LIMIT)
    offset = len(MAGIC) + HEADER.size

    def take(length):
        nonlocal offset
        _need(type(length) is int and 0 < length <= len(raw) - offset)
        value = raw[offset:offset + length]
        offset += length
        return value

    leaf, spki = take(leaf_length), take(spki_length)
    _need(hashlib.sha256(leaf).hexdigest() == expected, "p12_expected_certificate_mismatch")
    chain = []
    for _ in range(count):
        length = int.from_bytes(take(4), "big")
        _need(0 < length <= CERTIFICATE_LIMIT)
        der = take(length)
        _need(der != leaf and der not in chain)
        chain.append(der)
    _need(offset == len(raw))
    return leaf, spki, tuple(chain)


class P12Extraction:
    """A finite child record retained by ONE actual AppleProvisioningRun.

    It owns no new runner, pipe, clock or fallback. Its original material
    references survive early failures until actual child/scratch closure is
    known; a terminal/result-shaped object cannot retire those references.
    """
    __slots__ = ("_operation", "_source", "_runtime", "_material", "_expected",
                 "_started", "_claimed", "_complete", "_retired", "_scratch",
                 "_p12", "_password", "_result", "_facts", "_failure")

    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        _need(type(operation) is AppleProvisioningRun
              and operation.source.require_operation() is operation
              and operation.request.context["mode"] in MODES
              and getattr(operation, "_p12_extraction", None) is None)
        operation.checkpoint()
        self._operation, self._source, self._runtime = operation, operation.source, operation.runtime
        self._material = _material(self._source.profile_material(operation))
        self._expected = _selected_expected(operation)
        self._started = self._claimed = self._complete = self._retired = False
        self._scratch = self._p12 = self._password = self._result = self._facts = self._failure = None
        # Retain the original before finite_scratch constructs/acquires any FD.
        operation._p12_extraction = self

    def _binding(self, operation):
        _need(operation is self._operation and operation.source is self._source
              and operation.runtime is self._runtime and operation._p12_extraction is self
              and not self._retired and self._source.require_operation() is operation
              and self._source.profile_material(operation) is self._material)
        operation.checkpoint()
        self._runtime.require(root=operation.root, invocation=operation.invocation)
        _need(_selected_expected(operation) == self._expected)

    def bind_scratch(self, scratch):
        """Called by original operation.bind_scratch BEFORE native acquire.

        Retaining at constructor binding (not after context entry) preserves
        the original even when directory acquisition/entry itself fails.
        """
        _need(type(scratch) is FiniteScratch and self._scratch is None)
        self._scratch = scratch
        self._binding(self._operation)
        _need(self._started and not self._claimed and scratch.layout == LAYOUT
              and scratch.cancellation is self._operation.guard
              and scratch.journal is None and scratch._lane_binding is None
              and not scratch.active and not scratch.claimed and not scratch.created
              and scratch.slot.number is None and not scratch.parent.slots)

    def argv(self, runtime):
        self._binding(self._operation)
        _need(runtime is self._runtime and type(self._scratch) is FiniteScratch
              and self._p12 is not None and self._password is not None)
        return ("bundle", "exec", "ruby", str(runtime.tooling_root / "fastlane/apple_provisioning_p12.rb"),
                str(self._scratch.require(self._p12)), str(self._scratch.require(self._password)), self._expected)

    def admit_command(self, runtime, argv, *, environ):
        """Called by SAME operation.command_arguments before run_owned GO."""
        self._binding(self._operation)
        _need(self._started and not self._claimed and not self._complete and self._failure is None
              and tuple(argv) == self.argv(runtime) and type(environ) is dict
              and environ == self._operation._base_environment())
        self._claimed = True

    def run(self):
        self._binding(self._operation)
        _need(not self._started)
        self._started = True
        try:
            with finite_scratch(layout=LAYOUT, cancellation=self._operation.guard,
                                parent=self._runtime.private_directory) as scratch:
                _need(self._scratch is scratch)
                self._p12 = scratch.put("distribution-p12", self._material[3])
                self._password = scratch.put("p12-password", self._material[4])
                argv = self.argv(self._runtime)
                with self._runtime.command(argv, capture=True):
                    result = run_owned(argv, environ=self._operation._base_environment(),
                                       cwd=self._runtime.tooling_root, timeout=60, capture=True,
                                       text=False, output_limit=PRIVATE_OUTPUT_LIMIT,
                                       cancellation=self._operation.guard)
                    # Retain the original returned output before any decoding
                    # failure. The existing runner already owns its C/A/W joins.
                    self._result = result
                    _need(self._claimed and result.returncode == 0 and result.stderr == b"")
                    self._facts = parse_public_frame(result.stdout, self._expected)
                    scratch.require(self._p12)
                    scratch.require(self._password)
                    self._binding(self._operation)
            self._complete = True
            return self
        except BaseException as error:
            self._failure = True  # Original error is retained by operation.remember, not duplicated here.
            self._operation.remember(error)
            raise

    def current(self, operation):
        self._binding(operation)
        _need(self._complete and self._claimed and self._failure is None and self._facts is not None
              and self._scratch_closed())
        return True

    def certificate_inputs(self, operation):
        """PUBLIC leaf/full-SPKI/chain from this original, never a key loan."""
        self.current(operation)
        return self._facts

    def _scratch_closed(self):
        scratch = self._scratch
        return (scratch is not None and scratch.claimed and not scratch.active and scratch._cleanup_complete
                and not scratch.created and all(slot.number is None and slot.close_state == "CLOSED"
                    for slot in (*scratch.writer_slots, scratch.slot, *scratch.parent.slots)))

    def retire(self, operation):
        """Called after the SAME operation's cleanup, before private-input close.

        This retires only these Python references. It never says the native
        SavedSession, vault save, wrapping key or profile receiver is settled.
        """
        _need(operation is self._operation and operation._p12_extraction is self
              and operation.source is self._source and operation._close_claimed and operation._pending is None)
        if self._retired:
            return
        verdict = operation.guard.lifetime_ledger.verdict()
        # FiniteScratch/_Directory construction binds before their first IO.
        # No bound scratch means that fixed constructor never reached acquire;
        # a bound one must instead prove its ORIGINAL actual cleanup.
        no_scratch_acquired = self._scratch is None and not self._claimed
        _need(verdict.complete and not verdict.fatal and (no_scratch_acquired or self._scratch_closed()))
        self._material = None
        self._result = None
        self._retired = True

    def private_closed(self):
        return self._retired and self._material is None and self._result is None
