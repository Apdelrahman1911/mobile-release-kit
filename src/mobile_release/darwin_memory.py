"""One read-only Darwin free-page sample, not a memory reservation.

free_count already includes clean speculative pages. Inactive/purgeable pages
are deliberately not added. Kernel caching and concurrent workloads can make
this conservative sample stale; it is neither MemAvailable nor an RSS bound.
No native library or Mach port is acquired by importing this module.
"""
from __future__ import annotations

import ctypes
import sys
from typing import Callable

from .errors import ValidationError


class DarwinMemoryUnavailable(ValidationError):
    """No usable sample; any acquired host right was known retired."""


class DarwinMemoryCleanupUnknown(ValidationError):
    """An acquisition or consuming retirement did not return known finality."""


class _VMStatistics64Rev0(ctypes.Structure):
    _fields_ = [
        ("free_count", ctypes.c_uint32), ("active_count", ctypes.c_uint32),
        ("inactive_count", ctypes.c_uint32), ("wire_count", ctypes.c_uint32),
        ("zero_fill_count", ctypes.c_uint64), ("reactivations", ctypes.c_uint64),
        ("pageins", ctypes.c_uint64), ("pageouts", ctypes.c_uint64),
        ("faults", ctypes.c_uint64), ("cow_faults", ctypes.c_uint64),
        ("lookups", ctypes.c_uint64), ("hits", ctypes.c_uint64),
        ("purges", ctypes.c_uint64), ("purgeable_count", ctypes.c_uint32),
        ("speculative_count", ctypes.c_uint32),
    ]


def _unavailable() -> DarwinMemoryUnavailable:
    return DarwinMemoryUnavailable("A bounded free-memory sample is unavailable.")


def _bindings():
    # Fixed system library, never PATH/find_library or caller-selected code.
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    host_self = library.mach_host_self
    host_self.argtypes, host_self.restype = [], ctypes.c_uint32
    page_size = library.host_page_size
    page_size.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t)]
    page_size.restype = ctypes.c_int32
    statistics = library.host_statistics64
    statistics.argtypes = [ctypes.c_uint32, ctypes.c_int32,
                          ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint32)]
    statistics.restype = ctypes.c_int32
    deallocate = library.mach_port_deallocate
    deallocate.argtypes, deallocate.restype = [ctypes.c_uint32, ctypes.c_uint32], ctypes.c_int32
    # This task port is borrowed; only the returned host send-right is consumed.
    task_self = ctypes.c_uint32.in_dll(library, "mach_task_self_").value
    if not 0 < task_self < 0xffffffff:
        raise _unavailable()
    return host_self, page_size, statistics, deallocate, task_self


def sampled_free_bytes(*, check: Callable[[], None]) -> int:
    """Return a sample only after one known host-right retirement.

    The caller supplies its ORIGINAL deadline/cancellation check and must latch
    DarwinMemoryCleanupUnknown as unknown ownership, never as low memory or a
    tools-unavailable result. This routine never retries either acquisition or
    consuming deallocation. Workload thresholds belong to the existing owner.
    """
    check()
    if (sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_size_t) != 8
            or ctypes.sizeof(ctypes.c_int32) != 4 or ctypes.sizeof(ctypes.c_uint32) != 4
            or ctypes.sizeof(ctypes.c_uint64) != 8
            or ctypes.sizeof(_VMStatistics64Rev0) != 96
            or ctypes.alignment(_VMStatistics64Rev0) != 8
            or _VMStatistics64Rev0.zero_fill_count.offset != 16
            or _VMStatistics64Rev0.purgeable_count.offset != 88
            or _VMStatistics64Rev0.speculative_count.offset != 92):
        raise _unavailable()
    try:
        host_self, page_size, statistics, deallocate, task_self = _bindings()
    except (OSError, AttributeError, TypeError, ValueError) as error:
        raise _unavailable() from error
    check()
    # Allocate fixed output storage before acquiring the host send-right.
    pages = ctypes.c_size_t(0)
    values = _VMStatistics64Rev0()
    count = ctypes.c_uint32(24)  # Explicit supported REV0, not latest SDK size.
    host = None
    acquisition_pending = False
    primary = None
    unknown = None
    sample = None
    try:
        acquisition_pending = True
        host = host_self()
        acquisition_pending = False
        if type(host) is not int or not 0 < host < 0xffffffff:
            raise _unavailable()
        check()
        result = page_size(host, ctypes.byref(pages))
        if type(result) is not int or result != 0:
            raise _unavailable()
        check()
        if pages.value not in (4096, 16384):
            raise _unavailable()
        result = statistics(host, 4, ctypes.cast(ctypes.byref(values), ctypes.POINTER(ctypes.c_int32)),
                            ctypes.byref(count))
        if type(result) is not int or result != 0:
            raise _unavailable()
        check()
        if count.value != 24 or values.speculative_count > values.free_count:
            raise _unavailable()
        if values.free_count > ((1 << 64) - 1) // pages.value:
            raise _unavailable()
        sample = values.free_count * pages.value
    except BaseException as error:
        primary = error
    finally:
        # No clock failure is allowed to skip this consuming close. Once called,
        # any unreturned/nonzero result remains unknown; never retry the name.
        if type(host) is int and 0 < host < 0xffffffff:
            try:
                result = deallocate(task_self, host)
                if type(result) is not int or result != 0:
                    unknown = _unavailable()
            except BaseException as error:
                unknown = error
        elif acquisition_pending:
            unknown = primary
    if unknown is not None:
        raise DarwinMemoryCleanupUnknown("Free-memory probe ownership is unconfirmed; do not retry.") from (primary if primary is not None else unknown)
    if primary is not None:
        raise primary
    check()
    if type(sample) is not int:
        raise _unavailable()
    return sample
