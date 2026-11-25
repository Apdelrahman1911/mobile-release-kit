import tempfile
import unittest
from pathlib import Path

from desktop.tools import macos_release_media as media


class FrozenMediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.names = media.image_names("0.2.13")
        for name in self.names:
            (self.root / name).write_text(name)
        self.package = dict(bytes=10, sha256="e" * 64, descriptorSha256="f" * 64,
                            signatureSha256="1" * 64, developerIdApplicationLeafSha256="2" * 64)
        self.manifest = dict(schemaVersion=1, version="0.2.13", release="macos26-arm64-desktop-19",
                             target=media.TARGET, sourceCommit="a" * 40, sourceTree="b" * 40,
                             buildRun="100", buildAttempt="1", carrierRun="101", carrierAttempt="1",
                             images={name: media.record(self.root / name) for name in self.names},
                             packages={role + ".pkg": self.package.copy() for role in ("Install", "Remove")})
        self.write_manifest()

    def write_manifest(self):
        (self.root / media.MANIFEST).write_bytes(media.dump(self.manifest))
        (self.root / media.CHECKSUMS).write_bytes(media.checksum_bytes(self.root, (*self.names, media.MANIFEST)))

    def verify(self, source="a" * 40, tree="b" * 40, build="100", carrier="101"):
        return media.verify_frozen(self.root, source, tree, build, carrier)

    def test_rejects_wrong_source_tree_or_original_run(self):
        self.assertEqual(self.verify(), self.manifest)
        for changed in ({"source": "c" * 40}, {"tree": "c" * 40}, {"build": "109"}, {"carrier": "109"}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "release-manifest-source"):
                self.verify(**changed)

    def test_rejects_modified_media_and_unknown_asset(self):
        (self.root / "stale.dmg").write_bytes(b"another candidate")
        with self.assertRaisesRegex(ValueError, "release-asset-roster"):
            self.verify()
        (self.root / "stale.dmg").unlink()
        (self.root / self.names[0]).write_bytes(b"a replacement installer")
        with self.assertRaisesRegex(ValueError, "release-image-digests"):
            self.verify()

    def test_checksums_and_strict_media_leaves(self):
        (self.root / media.CHECKSUMS).write_text("wrong\n")
        with self.assertRaisesRegex(ValueError, "release-checksums"):
            self.verify()
        self.write_manifest()
        image = self.root / self.names[0]
        original = self.root / "original"
        image.rename(original)
        image.symlink_to(original)
        with self.assertRaises(OSError):
            media.record(image)

    def test_remove_producer_must_link_the_exact_install(self):
        source = "a" * 40
        version = self.manifest["version"]
        release = self.manifest["release"]
        current = dict(sourceCommit=source, release=release, packageVersion=version,
                       packageSha256=self.package["sha256"], inventorySha256="3" * 64,
                       signingPolicySha256="4" * 64)
        install = {}, self.package, dict(target=media.TARGET, releaseSet={"current": current})
        removal = dict(current, target=media.TARGET, installedProducerSha256=self.package["descriptorSha256"],
                       installedInventorySha256=current["inventorySha256"])
        def pair(descriptor):
            media.package_identities(install, ({}, self.package, descriptor),
                                     source=source, release=release, version=version)
        pair(removal)
        for key in ("installedProducerSha256", "installedInventorySha256", "signingPolicySha256"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "release-matching-pair"):
                pair(dict(removal, **{key: "0" * 64}))

    def test_draft_must_be_private_and_each_asset_must_match_the_frozen_roster(self):
        expected = {path.name: media.record(path) for path in self.root.iterdir()}
        rows = [dict(id=index, name=name, state="uploaded", size=record["bytes"], digest="sha256:" + record["sha256"])
                for index, (name, record) in enumerate(expected.items(), 1)]
        draft = dict(draft=True, prerelease=True, published_at=None, tag_name="desktop-v0.2.13",
                     target_commitish=self.manifest["sourceCommit"], assets=rows)
        self.assertEqual(media.draft_assets(draft, self.manifest, expected), rows)
        for changed in (dict(draft=False), dict(prerelease=False), dict(target_commitish="main"),
                        dict(assets=rows + [dict(rows[0], name="old.dmg")]),
                        dict(assets=[dict(rows[0], digest="sha256:" + "0" * 64), *rows[1:]])):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "release-(private-)?draft"):
                media.draft_assets(dict(draft, **changed), self.manifest, expected)
