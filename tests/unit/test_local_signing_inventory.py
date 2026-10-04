"""Inert DATA-only native inventory policy; no account, filesystem or process work."""
from __future__ import annotations

import stat
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import local_signing as signing
from mobile_release.errors import CredentialError


class NativeInventoryDataTests(unittest.TestCase):
    @staticmethod
    def facts(*, mode=0o600, size=0, uid=991, nlink=1, kind=stat.S_IFREG, inode=23):
        return SimpleNamespace(st_dev=17, st_ino=inode, st_mode=kind | mode,
                               st_size=size, st_uid=uid, st_nlink=nlink)

    def inventory(self, entries, *, owner_error=None, native_fd=51):
        owner = Mock(side_effect=owner_error)
        session = SimpleNamespace(assert_owner=owner, native_fd=native_fd)
        names = Mock(return_value=set(entries))
        def observe(name, *, dir_fd, follow_symlinks):
            self.assertEqual(dir_fd, native_fd)
            self.assertIs(follow_symlinks, False)
            return entries[name]
        operating_system = SimpleNamespace(getuid=lambda: 991, stat=Mock(side_effect=observe))
        forbidden = {name: Mock(side_effect=AssertionError("inventory must not mutate or acquire resources"))
                     for name in ("open", "chmod", "chown", "unlink", "rename", "replace")}
        for name, operation in forbidden.items():
            setattr(operating_system, name, operation)
        with patch.object(signing, "_names", names), patch.object(signing, "os", operating_system), \
                patch.object(signing.SigningSession, "run") as run, \
                patch.object(signing.SigningSession, "cleanup_native") as cleanup_native, \
                patch.object(signing.SigningSession, "cleanup_profile") as cleanup_profile:
            try:
                return signing.SigningSession.inventory(session)
            finally:
                owner.assert_called_once_with()
                run.assert_not_called()
                cleanup_native.assert_not_called()
                cleanup_profile.assert_not_called()
                for operation in forbidden.values():
                    operation.assert_not_called()
                if owner_error is not None or native_fd is None:
                    names.assert_not_called()
                    operating_system.stat.assert_not_called()
                elif set(entries) - {signing.DB_NAME, signing.LOCK_NAME}:
                    operating_system.stat.assert_not_called()
                else:
                    names.assert_called_once_with(native_fd)

    def test_database_and_empty_atomicfile_lock_have_distinct_role_policies(self):
        database = self.facts(size=64 * 1024 * 1024)
        self.assertEqual(self.inventory({signing.DB_NAME: database}),
                         {signing.DB_NAME: {"device": 17, "inode": 23}})
        for mode in (0o400, 0o404, 0o440, 0o444):
            lock = self.facts(mode=mode, inode=29)
            for rows in ({signing.LOCK_NAME: lock}, {signing.DB_NAME: database, signing.LOCK_NAME: lock}):
                with self.subTest(mode=oct(mode), names=tuple(rows)):
                    self.assertEqual(self.inventory(rows),
                                     {name: {"device": value.st_dev, "inode": value.st_ino}
                                      for name, value in rows.items()})
        self.assertEqual(self.inventory({}), {})
        self.assertEqual(self.inventory({}, native_fd=None), {})

    def test_wrong_role_permissions_sizes_and_common_ownership_fail_closed(self):
        invalid = [(signing.DB_NAME, self.facts(mode=mode)) for mode in (0o400, 0o640)]
        invalid.append((signing.DB_NAME, self.facts(size=64 * 1024 * 1024 + 1)))
        invalid += [(signing.LOCK_NAME, self.facts(mode=mode))
                    for mode in (0o600, 0o644, 0o420, 0o402, 0o500, 0o1400, 0o2400, 0o4400, 0o044)]
        invalid.append((signing.LOCK_NAME, self.facts(mode=0o400, size=1)))
        for name, mode in ((signing.DB_NAME, 0o600), (signing.LOCK_NAME, 0o400)):
            invalid += [(name, self.facts(mode=mode, **changes)) for changes in
                        ({"uid": 992}, {"nlink": 2}, {"kind": stat.S_IFLNK}, {"kind": stat.S_IFIFO})]
        for name, facts in invalid:
            with self.subTest(name=name, facts=vars(facts)), self.assertRaises(CredentialError):
                self.inventory({name: facts})
        for rows in ({"unknown": self.facts()}, {signing.DB_NAME: self.facts(), "unknown": self.facts()}):
            with self.subTest(names=tuple(rows)), self.assertRaises(CredentialError):
                self.inventory(rows)

    def test_owner_refusal_precedes_names_and_stat_without_resource_effects(self):
        failure = CredentialError("inert owner refused")
        with self.assertRaises(CredentialError) as caught:
            self.inventory({signing.LOCK_NAME: self.facts(mode=0o400)}, owner_error=failure)
        self.assertIs(caught.exception, failure)
