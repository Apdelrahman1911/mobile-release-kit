"""Inert profile-read handoff selection, never a native lifetime receipt."""
from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import checked_files
from workflow import local_signing_handoff_fixture as fixture


class ProfileHandoffSelectorTests(unittest.TestCase):
    """Only memory objects/stat scalars: no FD, fork, wait, signal or reader."""
    def setUp(self):
        for name in ("open", "close", "stat", "lstat", "fstat", "read", "fork", "waitpid", "kill", "killpg"):
            veto = patch.object(fixture.os, name, side_effect=AssertionError("inert selector attempted an OS operation"))
            veto.start()
            self.addCleanup(veto.stop)

    @staticmethod
    def sample():
        # These are inert stand-ins, not constructors/receipts for a real owner.
        thread = object()
        guard = SimpleNamespace(pid=17, owner_thread=thread)
        owner = SimpleNamespace(pid=17, owner_thread=thread, cancellation=guard, locked=True, active=None)
        parent = SimpleNamespace(st_dev=1, st_ino=2, st_uid=3, st_gid=4, st_mode=stat.S_IFDIR | 0o700)
        file = SimpleNamespace(st_dev=1, st_ino=5, st_uid=3, st_gid=4, st_mode=stat.S_IFREG | 0o600,
                               st_nlink=1, st_size=19, st_mtime_ns=7, st_ctime_ns=8)
        directory = fixture._directory_facts(parent)
        facts = fixture._file_facts(file)
        binding = {**facts, "sha256": "a" * 64}
        slot = SimpleNamespace(number=81, open_state="OPEN", close_state="NOT_ATTEMPTED")
        scratch = SimpleNamespace(pid=17, thread=thread, cancellation=guard, active=True, claimed=False,
            created=True, layout="signing-validation", parent=SimpleNamespace(path=Path("/fictional")),
            name="scratch", slot=slot, identity=directory, snapshots={}, tokens={}, records={})
        snapshot = SimpleNamespace(_owner=scratch, _role="apple-profile", _token=object(),
                                   size=facts["size"], sha256=binding["sha256"])
        scratch.snapshots["apple-profile"] = snapshot
        scratch.tokens["apple-profile"] = snapshot._token
        record = scratch.records["apple-profile"] = {"binding": binding}
        path = Path("/fictional/scratch/profile.mobileprovision")
        selected = dict(scratch=scratch, snapshot=snapshot, owner=owner, lease=owner, guard=guard, pid=17,
            record=record, binding=binding, token=snapshot._token, path=path, leaf="profile.mobileprovision",
            file=facts, directory_slot=slot, directory_fd=81, original_directory_identity=directory,
            directory=dict(directory))
        descriptor = SimpleNamespace(pid=17, owner_thread=thread, state="ACQUIRING", number=None,
                                     _child_close_claimed=False)
        scope = SimpleNamespace(pid=17, owner_thread=thread, cancellation=guard, _descriptors=(descriptor,),
                                claimed=False)
        reader = SimpleNamespace(f_code=fixture.ios_profiles.read_profile_bytes.__code__,
            f_locals=dict(path=path, descriptor=descriptor, scope=scope, guard=guard, cancellation=guard, entry=file))
        opening = SimpleNamespace(f_code=fixture.ios_profiles._ProfileDescriptor.open.__code__, f_back=reader,
            f_locals=dict(self=descriptor, path=path, flags=fixture._PROFILE_FLAGS, mode=0o600, dir_fd=None))
        return dict(selected=selected, opening=opening, reader=reader, path=path,
                    args=(fixture._PROFILE_FLAGS, 0o600), kwargs={"dir_fd": None},
                    parent_state=parent, leaf_state=file, returned_state=file)

    @staticmethod
    def matches(case):
        return fixture._profile_read_handoff_matches(case["selected"], case["opening"], case["reader"],
            case["path"], case["args"], case["kwargs"], case["parent_state"], case["leaf_state"], case["returned_state"])

    def test_only_original_unfilled_reader_of_the_selected_leaf_matches(self):
        case = self.sample()
        self.assertTrue(self.matches(case))
        descriptor = case["opening"].f_locals["self"]
        self.assertEqual(descriptor.state, "ACQUIRING")
        self.assertIsNone(descriptor.number)
        self.assertFalse(descriptor._child_close_claimed)
        self.assertFalse(case["reader"].f_locals["scope"].claimed)

    def test_wrong_callers_bindings_and_filled_slots_never_select(self):
        # Change one materially different selection boundary per row. These
        # negative data cases cannot create or settle native resources.
        changes = (
            ("unarmed", lambda c: c.update(selected=None)),
            ("initial-external-reader", lambda c: setattr(c["opening"], "f_code", checked_files._Reader._open.__code__)),
            ("other-read-caller", lambda c: setattr(c["reader"], "f_code", fixture.fictional_signing_profile.__code__)),
            ("not-immediate-reader", lambda c: setattr(c["opening"], "f_back", None)),
            ("external-source-path", lambda c: c.update(path=Path("/fictional/private/profile"))),
            ("different-read-flags", lambda c: c.update(args=(fixture._PROFILE_FLAGS | fixture.os.O_WRONLY, 0o600))),
            ("descriptor-relative-other-open", lambda c: c.update(kwargs={"dir_fd": 81})),
            ("different-scope", lambda c: setattr(c["reader"].f_locals["scope"], "_descriptors", (object(),))),
            ("different-guard", lambda c: c["reader"].f_locals.update(guard=object())),
            ("different-descriptor", lambda c: c["reader"].f_locals.update(descriptor=object())),
            ("already-filled-slot", lambda c: setattr(c["opening"].f_locals["self"], "number", 82)),
            ("wrong-role-leaf", lambda c: c["selected"].update(leaf="identity.p12")),
            ("retargeted-original-parent-fd", lambda c: setattr(c["selected"]["scratch"].slot, "number", 82)),
            ("different-parent-identity", lambda c: c.update(parent_state=SimpleNamespace(**{**vars(c["parent_state"]), "st_ino": 9}))),
            ("different-leaf-identity", lambda c: c.update(leaf_state=SimpleNamespace(**{**vars(c["leaf_state"]), "st_ino": 9}))),
            ("different-returned-fd-identity", lambda c: c.update(returned_state=SimpleNamespace(**{**vars(c["returned_state"]), "st_ino": 9}))),
            ("replacement-selection-token", lambda c: c["selected"]["scratch"].tokens.update({"apple-profile": object()})),
            ("replacement-binding-object", lambda c: c["selected"]["record"].update(binding=dict(c["selected"]["binding"]))),
        )
        for label, change in changes:
            with self.subTest(boundary=label):
                case = self.sample()
                change(case)
                self.assertFalse(self.matches(case))
