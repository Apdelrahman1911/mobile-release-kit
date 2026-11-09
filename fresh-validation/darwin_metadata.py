"""Exact read-only metadata definitions extracted from the existing reviewed helper.
No product entrypoint, process owner, write, or platform-version predicate.
"""
import ctypes
import errno
import sys

class Refused(Exception):
    """A bounded diagnostic code, not an accepted-error capability."""

def full9(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns]

class Timespec(ctypes.Structure):
    _fields_ = (("seconds", ctypes.c_int64), ("nanoseconds", ctypes.c_int64))

class DarwinStat(ctypes.Structure):
    _fields_ = (
        ("dev", ctypes.c_int32), ("mode", ctypes.c_uint16), ("links", ctypes.c_uint16),
        ("ino", ctypes.c_uint64), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("rdev", ctypes.c_int32), ("atime", Timespec), ("mtime", Timespec),
        ("ctime", Timespec), ("birthtime", Timespec), ("size", ctypes.c_int64),
        ("blocks", ctypes.c_int64), ("blksize", ctypes.c_int32),
        ("flags", ctypes.c_uint32), ("gen", ctypes.c_uint32), ("lspare", ctypes.c_int32),
        ("qspare", ctypes.c_int64 * 2),
    )

    def nine(self):
        for value in (self.mtime, self.ctime, self.birthtime):
            if not 0 <= value.nanoseconds < 1000000000:
                raise Refused("native-stat-nanoseconds")
        return [self.dev, self.ino, self.mode, self.uid, self.gid, self.links, self.size,
                self.mtime.seconds * 1000000000 + self.mtime.nanoseconds,
                self.ctime.seconds * 1000000000 + self.ctime.nanoseconds]

class DarwinStatFS(ctypes.Structure):
    _fields_ = (
        ("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32),
        ("blocks", ctypes.c_uint64), ("bfree", ctypes.c_uint64),
        ("bavail", ctypes.c_uint64), ("files", ctypes.c_uint64), ("ffree", ctypes.c_uint64),
        ("fsid", ctypes.c_int32 * 2), ("owner", ctypes.c_uint32), ("type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("subtype", ctypes.c_uint32),
        ("fstypename", ctypes.c_char * 16), ("mounton", ctypes.c_char * 1024),
        ("mountfrom", ctypes.c_char * 1024), ("flags_ext", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 7),
    )

class DarwinSigaction(ctypes.Structure):
    # Public userspace struct, NOT the larger kernel __sigaction trampoline ABI.
    _fields_ = (("handler", ctypes.c_void_p), ("mask", ctypes.c_uint32),
                ("flags", ctypes.c_int32))

def _check_abi():
    expected = {
        DarwinSigaction: (16, {"handler": 0, "mask": 8, "flags": 12}),
        DarwinStat: (144, {"dev": 0, "mode": 4, "links": 6, "ino": 8, "uid": 16,
                          "gid": 20, "rdev": 24, "atime": 32, "mtime": 48,
                          "ctime": 64, "birthtime": 80, "size": 96, "blocks": 104,
                          "blksize": 112, "flags": 116, "gen": 120, "lspare": 124,
                          "qspare": 128}),
        DarwinStatFS: (2168, {"bsize": 0, "iosize": 4, "blocks": 8, "fsid": 48,
                             "owner": 56, "type": 60, "flags": 64, "subtype": 68,
                             "fstypename": 72, "mounton": 88, "mountfrom": 1112,
                             "flags_ext": 2136, "reserved": 2140}),
    }
    if (ctypes.sizeof(ctypes.c_int) != 4 or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(ctypes.c_size_t) != 8 or sys.byteorder != "little"
            or ctypes.sizeof(Timespec) != 16):
        raise Refused("darwin-lp64-widths-required")
    for structure, (size, offsets) in expected.items():
        if ctypes.sizeof(structure) != size or ctypes.alignment(structure) != 8:
            raise Refused("darwin-lp64-structure-size")
        if any(getattr(structure, field).offset != offset for field, offset in offsets.items()):
            raise Refused("darwin-lp64-structure-offset")

def _call(function, *arguments):
    ctypes.set_errno(0)
    result = function(*arguments)
    return result, ctypes.get_errno()

def _acl_snapshot(library, descriptor, expected):
    """Same native empty-ACL rule. `expected` comes from this held FD's os.fstat.

    This function has no path lookup, ACL setter, FD transfer or errno-only
    absence shortcut. The mockable library seam is for DATA tests, not CLI input.
    """
    value = {"empty": False, "kind": "unavailable", "present": None, "phase": 0,
             "callResult": 0, "errno": 0, "aclFreeResult": None,
             "aclFreeErrno": None, "filesecFreeReturned": False}
    fsec = None
    acl = ctypes.c_void_p()
    owned_acl = False

    def fail(phase, returned, observed_errno):
        if value["phase"] == 0:
            value.update(phase=phase, callResult=returned, errno=observed_errno)

    try:
        fsec, observed_errno = _call(library.filesec_init)
        if not fsec:
            fail(1, 0, observed_errno)
        else:
            snapshot = DarwinStat()
            returned, observed_errno = _call(library.fstatx_np, descriptor,
                                             ctypes.byref(snapshot), fsec)
            if returned != 0:
                fail(2, returned, observed_errno)
            else:
                observed = snapshot.nine()
                value["snapshotFull9"] = observed
                value["snapshotFlags"] = snapshot.flags
                value["snapshotBirthtimeNs"] = (snapshot.birthtime.seconds * 1000000000
                                                + snapshot.birthtime.nanoseconds)
                if observed != expected:
                    fail(2, returned, 0)
                else:
                    for phase, prop, ctype, wanted in (
                            (3, 1, ctypes.c_uint32, snapshot.uid),
                            (4, 2, ctypes.c_uint32, snapshot.gid),
                            (5, 4, ctypes.c_uint16, snapshot.mode)):
                        actual = ctype()
                        returned, observed_errno = _call(library.filesec_get_property,
                                                         fsec, prop, ctypes.byref(actual))
                        if returned != 0 or actual.value != wanted:
                            fail(phase, returned, observed_errno if returned else 0)
                            break
                    if value["phase"] == 0:
                        present = ctypes.c_int()
                        returned, observed_errno = _call(library.filesec_query_property,
                                                         fsec, 5, ctypes.byref(present))
                        if returned != 0:
                            fail(6, returned, observed_errno)
                        else:
                            value["present"] = present.value
                            if present.value == 0:
                                value.update(empty=True, kind="absent")
                            else:
                                returned, observed_errno = _call(library.filesec_get_property,
                                                                 fsec, 5, ctypes.byref(acl))
                                if returned != 0:
                                    fail(7, returned, observed_errno)
                                elif acl.value in (None, 0, 1):
                                    fail(8, 0, 0)
                                else:
                                    owned_acl = True
                                    returned, observed_errno = _call(library.acl_valid, acl)
                                    if returned != 0:
                                        fail(9, returned, observed_errno)
                                    else:
                                        entry = ctypes.c_void_p()
                                        returned, observed_errno = _call(library.acl_get_entry,
                                                                         acl, 0, ctypes.byref(entry))
                                        if returned == 0:
                                            value["kind"] = "contains-entry"
                                            fail(11, returned, 0)
                                        elif returned == -1 and observed_errno == errno.EINVAL:
                                            value.update(empty=True, kind="empty-valid-acl")
                                        else:
                                            fail(10, returned, observed_errno)
    except Exception as error:
        value["exception"] = type(error).__name__
        fail(13, 0, 0)
    finally:
        if owned_acl:
            # Consume once even when the return is uncertain; do not retry free.
            owned_acl = False
            try:
                returned, observed_errno = _call(library.acl_free, acl)
                value["aclFreeResult"] = returned
                value["aclFreeErrno"] = observed_errno
                if returned != 0:
                    fail(12, returned, observed_errno)
                    value["empty"] = False
            except Exception as error:
                value["aclFreeException"] = type(error).__name__
                fail(12, 0, 0)
                value["empty"] = False
        if fsec:
            try:
                library.filesec_free(fsec)  # void API; successful return is required.
                value["filesecFreeReturned"] = True
            except Exception as error:
                value["filesecFreeException"] = type(error).__name__
                fail(14, 0, 0)
        if value["phase"] or not value["filesecFreeReturned"]:
            value["empty"] = False
    return value
