"""Real original metadata ZIP/tree, inert source Git; no SDK/Store/native."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
import test_local_release_metadata as source_fixture
from mobile_release import build_inputs as B
from mobile_release.local_store_metadata import StoreMetadataTree
from mobile_release.local_release_journal import canonical
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError


def archive(rows):
    with io.BytesIO() as data:
        with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_STORED) as z:
            for name,body in rows:
                info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED;info.external_attr=0o100644<<16
                z.writestr(info,body)
        return data.getvalue()

class StoreMetadataSourceTests(unittest.TestCase):
    setUp=source_fixture.LocalMetadataTests.setUp
    write=source_fixture.LocalMetadataTests.write
    command=source_fixture.LocalMetadataTests.command
    subject=source_fixture.LocalMetadataTests.subject
    scratch=source_fixture.LocalMetadataTests.scratch
    def test_same_positive_original_read_populates_zip_and_consumed_tree(self):
        with self.subject() as (source,metadata):
            scratch=self.scratch(source,metadata)
            with B._scope(scratch,source.guard,False):
                tree=StoreMetadataTree(scratch,platform='android')
                token=scratch.metadata_archive(self.metadata,platform='android',_source=metadata,_tree=tree)
                raw=scratch.require(token).read_bytes();row='android/en-US/title.txt'
                self.assertEqual((tree.path/row).read_bytes(),b'Reviewed title\n')
                self.assertEqual((tree.path/row).stat().st_mode&0o7777,0o444)
                with zipfile.ZipFile(io.BytesIO(raw)) as z:self.assertEqual(z.read(row),(tree.path/row).read_bytes())
                binding=tree.binding_data();self.assertEqual(binding['metadataSha256'],token.sha256)
                actual=tree.path.stat()
                self.assertEqual(binding['rootIdentity'],dict(device=str(actual.st_dev),inode=str(actual.st_ino),mode=actual.st_mode,uid=actual.st_uid,gid=actual.st_gid))
                tree.post();self.assertEqual(source.calls,7)
            self.assertTrue(tree.closed and tree.retired);self.assertFalse(scratch._path.exists())

class StoreMetadataTreeTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=Path.home());self.home=Path(self.temp.name)
        self.guard=DefaultCancellation(ProcessCleanupError,'test tree cleanup')
        self.scratch=B.FiniteScratch('store-metadata',self.guard,self.home);self.scratch.acquire()
    def tearDown(self):
        if not self.scratch.claimed:
            try:self.scratch.cleanup()
            except BaseException:pass
        self.assertTrue(all(s.number is None for s in [self.scratch.slot,*self.scratch.parent.slots,*self.scratch.writer_slots]))
        self.temp.cleanup()
    def tree(self,rows,platform='ios'):
        token=self.scratch.put('metadata',archive(rows));tree=StoreMetadataTree(self.scratch,platform=platform)
        tree.from_snapshot(token);return tree,token
    def test_current_snapshot_tree_three_roots_and_exact_roster_digest(self):
        rows=[('ios/en-US/description.txt',b'A retained description\n'),('review/ios-notes.txt',b'Notes\n'),('testflight/what-to-test.txt',b'Test notes\n')]
        tree,token=self.tree(rows);binding=tree.binding_data()
        expected=[dict(path=name,kind='file',bytes=len(data),sha256=hashlib.sha256(data).hexdigest()) for name,data in rows]
        expected += [dict(path=p,kind='directory') for p in ('ios','ios/en-US','review','testflight')]
        expected.sort(key=lambda r:r['path'].encode())
        self.assertEqual(binding['rosterSha256'],hashlib.sha256(b'mrk-local-store-metadata-tree/1\0'+canonical(expected)+b'\n').hexdigest())
        for name,body in rows:self.assertEqual((tree.path/name).read_bytes(),body)
        tree.post();self.scratch.cleanup();self.assertTrue(tree.closed and tree.retired)
    def test_traversal_foreign_platform_alias_and_duplicate_refuse_before_tree_creation(self):
        # One initial fixture per malformed archive; no accepting a replacement token.
        for names in (('../private.txt',),('android/title.txt',),('ios/a.txt','ios/A.txt'),('ios/a.txt','ios/a.txt')):
            if self.scratch.records:
                self.scratch.cleanup();self.scratch=B.FiniteScratch('store-metadata',self.guard,self.home);self.scratch.acquire()
            token=self.scratch.put('metadata',archive([(n,b'inert') for n in names]))
            tree=StoreMetadataTree(self.scratch,platform='ios')
            with self.assertRaises(Exception):tree.from_snapshot(token)
            self.assertFalse(tree.path.exists());self.assertEqual(tree.slots,[])
    def test_original_leaf_change_preserves_unknown_tree_and_drains_all_fds(self):
        tree,_=self.tree([('ios/a.txt',b'original')]);path=tree.path/'ios/a.txt'
        path.chmod(0o600);path.write_bytes(b'foreign!');path.chmod(0o444)
        with self.assertRaises(Exception):tree.post()
        with self.assertRaises(Exception):self.scratch.cleanup()
        self.assertTrue(tree.failed);self.assertTrue(tree.closed);self.assertFalse(tree.retired)
        self.assertEqual(path.read_bytes(),b'foreign!')
        self.assertTrue(all(s.number is None for s in tree.slots+tree.writer_slots))
    def test_consumers_unknown_prevent_tree_deletion_and_still_close_originals(self):
        tree,_=self.tree([('ios/a.txt',b'original')]);target=tree.path
        from types import SimpleNamespace
        with patch.object(type(self.guard.lifetime_ledger),'verdict',return_value=SimpleNamespace(complete=False,fatal=True,contained=True)):
            with self.assertRaises(Exception):self.scratch.cleanup()
        self.assertTrue(target.exists());self.assertTrue(tree.closed);self.assertFalse(tree.retired)
    def test_file_and_directory_prefix_collision_and_directory_cap_refuse_before_effect(self):
        tree=StoreMetadataTree(self.scratch,platform='ios')
        with self.assertRaises(Exception):tree.begin(('ios/a.txt','ios/a.txt/inside.txt'))
        self.assertFalse(tree.path.exists())
        with self.assertRaises(Exception):tree.begin(tuple(f'ios/d{n:03d}/a.txt' for n in range(97)))
        self.assertFalse(tree.path.exists())

    def test_false_central_count_refuses_before_stdlib_decoder_allocation(self):
        raw=bytearray(archive([('ios/a.txt',b'A'),('ios/b.txt',b'B')]))
        import struct
        struct.pack_into('<HH',raw,len(raw)-22+8,1,1)
        token=self.scratch.put('metadata',bytes(raw));tree=StoreMetadataTree(self.scratch,platform='ios')
        with patch.object(zipfile,'ZipFile',side_effect=AssertionError('must preflight real central count')):
            from mobile_release.local_release_journal import LocalJournalError
            with self.assertRaises(LocalJournalError):tree.from_snapshot(token)
        self.assertFalse(tree.path.exists())
