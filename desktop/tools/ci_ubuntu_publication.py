"""Fixed disposable Ubuntu publication and installed-passive verification jobs.

Nonroot preparation reuses the ordinary owner. A separately pinned, manager-owned
root entry performs the fixed lifecycle. Only the separate installed route can
launch the freshly compiled feature-off test candidate and its fixed A payload.
This is not a product/consumer capability or a general privileged runner.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib

SOURCE = Path(__file__).absolute().parents[2]


def local(name):
    spec = importlib.util.spec_from_file_location("_publisher_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = local("conventional_runtime_data")
C = local("ci_foundation")
REF = "refs/heads/verify/desktop-ubuntu-publication"
INSTALLED_REF = "refs/heads/verify/desktop-installed-passive"
INSTALLED_CASES = {"positive", "refuse-writable", "refuse-pth"}
SHELL_REF = "refs/heads/verify/desktop-installed-shell"
SHELL_FEATURES = ["custom-protocol", "desktop-shell"]
SHELL_FEATURE_ARG = "desktop-shell,custom-protocol"
SHELL_PERMISSIONS = "desktop/src-tauri/permissions"
SHELL_GENERATED = ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen", SHELL_PERMISSIONS)
SHELL_CLEANUP_SUCCESS = {"generatedRootsRemoved": list(SHELL_GENERATED), "workRemoved": True,
                         "sourceClean": True, "originalOwnersReturned": True, "exportsRetained": True}
SHELL_EXPORTS = {"normal": "mobile-release-kit-desktop", "observer": "installed-shell-observation"}
SHELL_METADATA_LIMIT = 8 << 20
SHELL_COMPILE_LIMIT = 8 << 20
SHELL_ROSTER_LIMIT = 512 << 10
SHELL_WEBKIT_PROGRAMS = (
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess",
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess",
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitGPUProcess",
    "/usr/bin/bwrap", "/usr/bin/xdg-dbus-proxy",
)
SHELL_LIBRARY_ROOT = "/usr/lib/x86_64-linux-gnu"
# These are per-requester RUNPATH exceptions, not additional global loader
# directories. The selected link and its canonical package member are both
# independently protected/bound before any bytes can enter this profile.
SHELL_RUNPATHS = {
    SHELL_LIBRARY_ROOT + "/libproxy.so.1": ("libproxy.so.1", SHELL_LIBRARY_ROOT + "/libproxy"),
    SHELL_LIBRARY_ROOT + "/libproxy/libpxbackend-1.0.so":
        ("libpxbackend-1.0.so", SHELL_LIBRARY_ROOT + "/libproxy"),
    SHELL_LIBRARY_ROOT + "/libpulse.so.0": ("libpulse.so.0", SHELL_LIBRARY_ROOT + "/pulseaudio"),
    SHELL_LIBRARY_ROOT + "/libpulse-simple.so.0": ("libpulse-simple.so.0", SHELL_LIBRARY_ROOT + "/pulseaudio"),
}
SHELL_PRIVATE_PROVIDERS = {
    "libpxbackend-1.0.so": SHELL_LIBRARY_ROOT + "/libproxy",
    "libpulsecommon-16.1.so": SHELL_LIBRARY_ROOT + "/pulseaudio",
}
SHELL_RUNPATHS[SHELL_LIBRARY_ROOT + "/libLLVM.so.20.1"] = ("libLLVM.so.20.1", "$ORIGIN/../lib")
SHELL_RUNPATH_DIRECTORIES = {path: [runpath] for path, (_, runpath) in SHELL_RUNPATHS.items()
                             if not runpath.startswith("$ORIGIN")}
# The retained LLVM provider is directly in the multiarch directory. Also
# account for the loader's /lib usr-merge spelling, without admitting either
# directory as a source of a new provider.
SHELL_RUNPATH_DIRECTORIES[SHELL_LIBRARY_ROOT + "/libLLVM.so.20.1"] = ["/usr/lib/lib", "/lib/lib"]
SHELL_PROGRAMS = (*SHELL_WEBKIT_PROGRAMS, "/usr/bin/Xvfb", "/usr/bin/xdotool", "/usr/bin/xauth", "/usr/bin/prlimit",
    "/usr/bin/xkbcomp", "/usr/bin/dbus-daemon", "/usr/bin/dbus-run-session", "/bin/sh",
    *("/usr/bin/" + name for name in ("stty", "awk", "getopt", "mcookie", "fmt", "cat", "rm", "mktemp", "touch")),
    SHELL_LIBRARY_ROOT + "/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner")
SHELL_SCRIPTS = ("/usr/bin/xvfb-run",)
SHELL_MODULE_ROOTS = tuple(SHELL_LIBRARY_ROOT + suffix for suffix in (
    "/gio/modules", "/gdk-pixbuf-2.0/2.10.0/loaders", "/dri", "/gbm", "/gstreamer-1.0", "/enchant-2",
    "/webkit2gtk-4.1/injected-bundle",
    *("/gtk-3.0/" + prefix + leaf for prefix in ("3.0.0/linux/", "3.0.0/", "linux/", "")
      for leaf in ("immodules", "modules"))))
SHELL_MAX_LIBRARIES = 256  # Historical DATA already requires >214 names; fail closed beyond this fixed cap.
SHELL_TOOLS_JDK_ROOT = "/usr/lib/jvm/java-17-openjdk-amd64"
SHELL_TOOLS_PROGRAMS = ("/usr/bin/git", "/usr/bin/python3.12", SHELL_TOOLS_JDK_ROOT + "/bin/java", SHELL_TOOLS_JDK_ROOT + "/bin/javac")
SHELL_TOOLS_LINKS = {"/usr/bin/java": "/etc/alternatives/java", "/usr/bin/javac": "/etc/alternatives/javac",
    "/etc/alternatives/java": SHELL_TOOLS_JDK_ROOT + "/bin/java", "/etc/alternatives/javac": SHELL_TOOLS_JDK_ROOT + "/bin/javac"}
SHELL_TOOLS_DIRECTORIES = ("/", "/usr", "/usr/bin", "/usr/lib", "/usr/lib/jvm", SHELL_TOOLS_JDK_ROOT,
    SHELL_TOOLS_JDK_ROOT + "/bin", "/etc", "/etc/alternatives")
SHELL_TOOLS_PACKAGES = ("git", "python3.12", "openjdk-17-jdk-headless", "openjdk-17-jre-headless")

SHELL_TOOLS_NAMESPACE_PARENT = "/usr/lib/jvm"
SHELL_TOOLS_NAMESPACE_PARENTS = ("/", "/usr", "/usr/bin", "/usr/lib", "/etc", "/etc/alternatives")
SHELL_TOOLS_NAMESPACE_SOURCES = {".github/workflows/desktop-ubuntu-publication.yml": 64 << 10,
                                 "desktop/tools/ci_ubuntu_publication.py": 1 << 20}
SHELL_TOOLS_NAMESPACE_FILES = {"namespace-before.json": 64 << 10, "namespace.stdout": 16 << 10,
                              "namespace.stderr": 4096, "namespace.exit": 4}
SHELL_TOOLS_JDK_MISSING = (b"dpkg-query: no packages found matching openjdk-17-jdk-headless\n"
                         b"dpkg-query: no packages found matching openjdk-17-jre-headless\n")
# Independently accepted U35783044845/1: original lifecycle and finality.
# Complete producer-bound roster; every downloaded member is checked before use.
# This evidence qualifies neither the new installed candidate nor the product.
INSTALLED_U_INPUTS = {
    "sourceSha": "1ec7314cf7dd722eba4ad14257d2009c8dad488e",
    "runId": "35783044845",
    "attempt": "1",
    "artifactId": "10718458518",
    "files": [
        {"path": "F1.deb", "sha256": "e17e6ce20b68922cf3a215094b92a59f3beb9745cb324e1403aa499bd30fd734", "size": 312412352},
        {"path": "P0.deb", "sha256": "5c670a5edf0f29e69fd38dd97706a52f51e76b875f52bef5195dd14f438583c9", "size": 312412352},
        {"path": "acquired-head.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "acquired-head.stdout", "sha256": "e8a0ab067206caccf82916da9b4b320ba192f276fd3d838e166d5fcd1e191851", "size": 41},
        {"path": "acquired-status.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "acquired-status.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "after-head.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "after-head.stdout", "sha256": "e8a0ab067206caccf82916da9b4b320ba192f276fd3d838e166d5fcd1e191851", "size": 41},
        {"path": "after-status.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "after-status.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-head.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-head.stdout", "sha256": "e8a0ab067206caccf82916da9b4b320ba192f276fd3d838e166d5fcd1e191851", "size": 41},
        {"path": "before-root-head.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-root-head.stdout", "sha256": "e8a0ab067206caccf82916da9b4b320ba192f276fd3d838e166d5fcd1e191851", "size": 41},
        {"path": "before-root-status.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-root-status.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-status.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "before-status.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "cargo-selection.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "cargo-selection.stdout", "sha256": "8bca4bde57cb4684b1ccce5e00f799ecb6c4f56112c724e1e5a88578db033e76", "size": 132},
        {"path": "compiled-head.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "compiled-head.stdout", "sha256": "e8a0ab067206caccf82916da9b4b320ba192f276fd3d838e166d5fcd1e191851", "size": 41},
        {"path": "compiled-status.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "compiled-status.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "compiler-F1.json", "sha256": "ac137f6d3b9b1447f5ea2c57043b553b4587371130b1bf04de0106114ac3a588", "size": 635},
        {"path": "compiler-P0.json", "sha256": "c1ab70720602c655f4dfa45f718aef478a3c251793afc8f8369119ce13f34e70", "size": 632},
        {"path": "compiler-fixture.json", "sha256": "eae8b890f243bfcd56ad01e62e74494d411ca41f266bf29c260ea67022a8d00f", "size": 580},
        {"path": "compiler-libtest.json", "sha256": "6e679ef44689c0baf5b04e1fb62f18e456e96d2e63f270ee9d4195526ff05745", "size": 651},
        {"path": "compiler.json", "sha256": "18aea8d036a83f29b0da00374f716573a46a1fd0c94ecd920d3ced70e10f0591", "size": 94666},
        {"path": "deb-build-F1.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "deb-build-F1.stdout", "sha256": "650e524496f4ca9698f925c538931d642cde09b6641a29a5b043fa40a78c7fcb", "size": 143},
        {"path": "deb-build-P0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "deb-build-P0.stdout", "sha256": "9255479e81fd72d9443143f82a33ec30e3d9e938809d7fb68ecaff17c96cbc4d", "size": 143},
        {"path": "fixture-app", "sha256": "1035e72810205075e5dc5a7d4f238015eebcfb92981c16811be26d4b09725375", "size": 4501512},
        {"path": "fixture-compile.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "fixture-compile.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "fixture.rs", "sha256": "f6025e945b951f4bcd6fd01da8be1cca44f04f292b1bb00f11d6bde8f225cf96", "size": 38},
        {"path": "kernel-packages.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "kernel-packages.stdout", "sha256": "7eb291cfd444858529d37c0869507eeca8e235b938dad14f9fe7f830e192f09f", "size": 290},
        {"path": "kernel-selector.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "kernel-selector.stdout", "sha256": "82aa69c787d486c971aa0d018928eb8b03145e753fa2013f112c871f6c8448d3", "size": 189},
        {"path": "libtest", "sha256": "7770abc5bc836bdaa309edc2a1aad729101c78f7833deda1f32241bca9a4738a", "size": 29018840},
        {"path": "libtest-compile.stderr", "sha256": "18c310dbcf138a0a81b82e5c3fa974397a0df66e5d9d2109a80ed41ed14e441b", "size": 1362},
        {"path": "libtest-compile.stdout", "sha256": "83019e7d05b8f94e27b4ed81204df0c84d8d238a2ef371122563eba830ea132d", "size": 411642},
        {"path": "lifecycle-binaries-unpacked.json", "sha256": "dd7945a54dea853e7bb89a6988f2516741a02e08bf2018412dc2f68686a4fb62", "size": 473},
        {"path": "lifecycle-binaries-upgrade.json", "sha256": "454d1e57ed7171e43691461e80214eaa38a5081b0c7aae4269308007b3385d58", "size": 473},
        {"path": "lifecycle-client.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-client.stdout", "sha256": "668e34f3b738ae5ca8af5d91743e6fe1d236c0c875a0b863df625e917110d5bf", "size": 109},
        {"path": "lifecycle-configure.stderr", "sha256": "cb9277feeaf7900ddc2fd0dbad25556ce5920f65a500038a9afe1616667d9397", "size": 89},
        {"path": "lifecycle-configure.stdout", "sha256": "4c3d415d83a0d67f6cc5de6d323083fb43e90cfa57e65f5f78c1377b724c45b5", "size": 142},
        {"path": "lifecycle-dpkg-policy.json", "sha256": "b207246c1738a9fc9b9def6fa3775d985428eb48865ed025ef798ae12719ffc0", "size": 4585},
        {"path": "lifecycle-duplicate.stderr", "sha256": "0ef25c1e2c33385e1b95c5e0c5c2d6e0eac6c53d58787bde8e62ca9869e73a69", "size": 1483},
        {"path": "lifecycle-duplicate.stdout", "sha256": "6a0fae4b065fb455db10455f705bf17cfd87426cf29c21d5ebc0b4f21ee2797c", "size": 276},
        {"path": "lifecycle-inputs.json", "sha256": "aaa34608146c75569e5652fe6b9dea3f587f680dc0575d7db693531d894f9473", "size": 95808},
        {"path": "lifecycle-mutation-denials.txt", "sha256": "d3900e18332f28f6f2dc07b287818220f6e16f499a4507f192733300d95895f9", "size": 1447},
        {"path": "lifecycle-native-root.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-native-root.stdout", "sha256": "8d9f0492793ae74300439d876019b62077154f1a008428e01a061b0790a83ce7", "size": 197},
        {"path": "lifecycle-native-user.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-native-user.stdout", "sha256": "c364f073643918170cf144e671e3c5a18b94928d814431af7cbcf184839f16ab", "size": 198},
        {"path": "lifecycle-nonroot-helper.stderr", "sha256": "a75fe26ceeebd7df5c4d046a02d306f04ea88d4a42ce345555433114675ebb4f", "size": 174},
        {"path": "lifecycle-nonroot-helper.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-duplicate.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-duplicate.stdout", "sha256": "08d04e0bd63321e49adfdceccc6f22fe3d370557c2c3776af459647837dbd89e", "size": 276296},
        {"path": "lifecycle-observe-p0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-p0.stdout", "sha256": "4afb0884d80528caf3d4a3e81d91fff8a1836c9e080f2348c91a6fcba92b5041", "size": 276136},
        {"path": "lifecycle-observe-purge.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-purge.stdout", "sha256": "b588f6f3397cace1b83480ac9fa8e0aa848901d55434c28b8cb04804df5635e6", "size": 276292},
        {"path": "lifecycle-observe-remove.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-remove.stdout", "sha256": "10d7f63536e4321001dc516417d03d0277e91fff4ad5d90532193461a97f3919", "size": 276293},
        {"path": "lifecycle-observe-unpacked.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-unpacked.stdout", "sha256": "b0a62353d2637be4e1643856a08b97174b57b2b299ecec7a8a98048a7b68fcf4", "size": 137859},
        {"path": "lifecycle-observe-upgrade.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-observe-upgrade.stdout", "sha256": "6e1cf3097ac50c5870b241f723debef8780656bf66be4acc4d3b46f8518c7f56", "size": 414078},
        {"path": "lifecycle-published-after-duplicate.txt", "sha256": "edf70ab82c8aa6579fd3786aa73e739b650dd1e9334c948fd593cee943267a00", "size": 275570},
        {"path": "lifecycle-published-after-purge.txt", "sha256": "edf70ab82c8aa6579fd3786aa73e739b650dd1e9334c948fd593cee943267a00", "size": 275570},
        {"path": "lifecycle-published-after-remove.txt", "sha256": "edf70ab82c8aa6579fd3786aa73e739b650dd1e9334c948fd593cee943267a00", "size": 275570},
        {"path": "lifecycle-published-after-upgrade.txt", "sha256": "edf70ab82c8aa6579fd3786aa73e739b650dd1e9334c948fd593cee943267a00", "size": 275570},
        {"path": "lifecycle-published-before-upgrade.txt", "sha256": "ef69a14656b18d9add2ab053dbd36ab371f10e6f0f1b20648130e0ddc336ec25", "size": 137786},
        {"path": "lifecycle-purge.stderr", "sha256": "8b6571b7c06cc6e2c89c1d4125d23aee98ac3ad846a2f2a4704ec0ea7e40d9ed", "size": 82},
        {"path": "lifecycle-purge.stdout", "sha256": "e2734c29e4fb52bd84fd2f26f924f1999dceabf0bb376eca996287efa28bfd49", "size": 160},
        {"path": "lifecycle-remove.stderr", "sha256": "cd97eb555af1f9c7e0db23ed401483d9f3b88b6d8b40db0f1c662ee8e7c124db", "size": 434},
        {"path": "lifecycle-remove.stdout", "sha256": "4973803ea17208a7fe1e9719ad59b32e1f533f5b312cc9a8e43f89191a64ad8b", "size": 137},
        {"path": "lifecycle-scripts-before-upgrade.json", "sha256": "368949589a4f73a18551cee12e6049214cd5a2fa2b850f231a4667d4dadc48f4", "size": 730},
        {"path": "lifecycle-scripts-duplicate.json", "sha256": "f058d29afdaf9a0dcb567e60df41dac8ee1dba888c03534d74cd88278c46d66a", "size": 730},
        {"path": "lifecycle-scripts-purge.json", "sha256": "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356", "size": 3},
        {"path": "lifecycle-scripts-remove.json", "sha256": "f7c6cd3b5c66802a7e0b1842190baba1f33c8fa947c8a5f2062b16b960e1f1b7", "size": 244},
        {"path": "lifecycle-scripts-unpacked.json", "sha256": "368949589a4f73a18551cee12e6049214cd5a2fa2b850f231a4667d4dadc48f4", "size": 730},
        {"path": "lifecycle-scripts-upgrade.json", "sha256": "3bb2197988c8bd1f6f84094f8efb3417152a03ffcfd93d84f4f12cde72e215b2", "size": 730},
        {"path": "lifecycle-start-unit-show.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-start-unit-show.stdout", "sha256": "02579a19b9583d4a06eab456f6eb3fb63ec0a4310c049af9e6204e4c5427730c", "size": 578},
        {"path": "lifecycle-state-duplicate.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-duplicate.stdout", "sha256": "278598bf429592cb02fc8b25a9e69fee793c72ea27b364e3226d6252c7523794", "size": 49},
        {"path": "lifecycle-state-initial.stderr", "sha256": "01042c2b38915cf55a07ca91be671bf863ee638cc5974c9350091e541076bf8a", "size": 66},
        {"path": "lifecycle-state-initial.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-p0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-p0.stdout", "sha256": "e20752202f94a3dd2d6580c09a159dcef5a48420e2252055e30ce91407d8e801", "size": 43},
        {"path": "lifecycle-state-purge.stderr", "sha256": "01042c2b38915cf55a07ca91be671bf863ee638cc5974c9350091e541076bf8a", "size": 66},
        {"path": "lifecycle-state-purge.stdout", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-remove.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-remove.stdout", "sha256": "0f50a168546b15c82664db4f3366851b32e327d1a380d23d938c612abaf36ad2", "size": 48},
        {"path": "lifecycle-state-unpacked.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-unpacked.stdout", "sha256": "23dcbc6440890f94126d7b66936c8160fc35a4060daded116ec44fd86832b1d2", "size": 42},
        {"path": "lifecycle-state-upgrade.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-state-upgrade.stdout", "sha256": "dde135efd3a6186b9d7a27a1a3bdd7d2cdc1bd9abdf11e35af8ec1fee8a3f6c2", "size": 43},
        {"path": "lifecycle-stop-unit-show.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "lifecycle-stop-unit-show.stdout", "sha256": "02579a19b9583d4a06eab456f6eb3fb63ec0a4310c049af9e6204e4c5427730c", "size": 578},
        {"path": "lifecycle-unit-result.json", "sha256": "52a22f98fbee430787fa1519171a0a385fc7f3246871760da78c93871589fa33", "size": 19893},
        {"path": "lifecycle-unit-start.json", "sha256": "3d1d751994f4e7caf22cc4eae74a79629ffc8dce942514a0d184ce2bf078f669", "size": 1354},
        {"path": "lifecycle-unit-stop.json", "sha256": "3cc6bc9e775a4a7d70c17bbd6ca305e1d24898ae11caed0e806bf5d5444cdc58", "size": 2282},
        {"path": "lifecycle-unpack.stderr", "sha256": "deff21ac2546a815780222cfb42f071efb719ed60c037139a28a53e8029714f2", "size": 713},
        {"path": "lifecycle-unpack.stdout", "sha256": "102e930374ddfa07b114422741551fedeceaab467a06edde7cfd6710d8b873de", "size": 249},
        {"path": "lifecycle-upgrade.stderr", "sha256": "5494c7f69d0db3faac28e811c4e6fb1434ce9309733ae0fecc52c7d6b1ee4bd5", "size": 1073},
        {"path": "lifecycle-upgrade.stdout", "sha256": "deb86711f47c8d6473d02bdabb31e3d409110edefae508cbcddf432cf48c738f", "size": 352},
        {"path": "locked-inputs.stderr", "sha256": "22866d80086feac269ee5209841d8a2f5b219cffc402bf399227ef50e42bd15f", "size": 1085},
        {"path": "locked-inputs.stdout", "sha256": "0261d66f33b7eaf4fc1346758804173138fe35bc38a7d40251cd6394f7b6b9b1", "size": 221847},
        {"path": "mrk-runtime-publish", "sha256": "c25eeeb7b6fe774b43d485aeaedeb38a3a1c29b8d003e73a3e128d069c8bde68", "size": 995168},
        {"path": "mrk-runtime-publish-F1", "sha256": "b118fc4870f7987db8c696c324a36edc80fbe865ae613fa35cb7e8cda6089549", "size": 995168},
        {"path": "native-file-owner-1.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-1.stdout", "sha256": "406ecb79cc447cf72749ab0591bc1aa03582603d084238183d667848ad135175", "size": 58},
        {"path": "native-file-owner-11.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-11.stdout", "sha256": "1e9739b55ea192ca2372fe8f04d898535d9dec3745453901d6a690e5bf8a595b", "size": 50},
        {"path": "native-file-owner-12.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-12.stdout", "sha256": "5553b1e417ef0dfe2f9286739767eb4358e5c9133722590524bb15e765ac3330", "size": 50},
        {"path": "native-file-owner-13.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-13.stdout", "sha256": "0bc27d9c48943f7f8308f4b29a3db1224f6b379ccb95a5e5195ce2484a41365b", "size": 66},
        {"path": "native-file-owner-15.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-15.stdout", "sha256": "a8f22937e491e41acb225cef75857fad430332f446fb818807124b7a7c22e8bf", "size": 64},
        {"path": "native-file-owner-16.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-16.stdout", "sha256": "1cf4616364cddb65333f6f3df26f4c9f5cb2ba58a2723f367a68594e5ba1bae6", "size": 63},
        {"path": "native-file-owner-17.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-17.stdout", "sha256": "917fa231e7bfc71b524a9c9f2692de9094c8690c6a7bd3ed1ec5ff82a89ff088", "size": 66},
        {"path": "native-file-owner-18.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-18.stdout", "sha256": "46a530100f83f0f3f4da50e23e4f4b9d4a6b19b5f1769fa5ff5937b205fbaa64", "size": 66},
        {"path": "native-file-owner-19.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-19.stdout", "sha256": "b5d1a6cd1ea5f039060bb66c60ea0f804ae8fcc8a71abf9f8c5dbb010512a136", "size": 51},
        {"path": "native-file-owner-20.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-20.stdout", "sha256": "7bef47f55b6290d0d41c0563cc118328cab1f8c767c52501497383800c49018a", "size": 60},
        {"path": "native-file-owner-21.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-21.stdout", "sha256": "ebb20bdcd611227e9459e7651d116896bd3b7ff2c3cd737abbe6d47d30e1b9fc", "size": 53},
        {"path": "native-file-owner-22.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-22.stdout", "sha256": "29c38f8b1a353dc7bc301fb3028e00a33f331aedac511107dc1262b630712834", "size": 51},
        {"path": "native-file-owner-23.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-23.stdout", "sha256": "e8dc021178ca0906683a10c7e72d5bc80567f66daadb563fe5facaf27a4f6157", "size": 56},
        {"path": "native-file-owner-24.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-24.stdout", "sha256": "baa61f16fe32eedf563174e77c0991dc147af8700cd032ee66f83375927b9f27", "size": 51},
        {"path": "native-file-owner-25.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-25.stdout", "sha256": "b9ccbcfb5e1e3080ca7fc9615afc9bbc26c9e2670fd83cd256c14709e7507e3e", "size": 51},
        {"path": "native-file-owner-4.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-4.stdout", "sha256": "026d3279f665db5e5cab3732151b5a6efc93e8b462548124c02ce22132f09cd9", "size": 71},
        {"path": "native-file-owner-5.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-5.stdout", "sha256": "0da5619d7511c8f9b3a45a187a9e0611ad950a20658ff68c514d9411a18373e4", "size": 60},
        {"path": "native-file-owner-9.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-file-owner-9.stdout", "sha256": "cd8243d8e763c1d72b83fe67d46cc6567f98820197df6f9ebb5e8706ca948cd8", "size": 51},
        {"path": "native-gcc-program-collect2.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-program-collect2.stdout", "sha256": "c0b7638fa61ef43107d74ccefe76e6f9cd3c061bfee7d6ffd58a7b783012afed", "size": 46},
        {"path": "native-gcc-program-ld.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-program-ld.stdout", "sha256": "3b6cb8ae51045d062a7c7de7cc488ad8785144cfbc0a7fc9546ed52429e0d97f", "size": 3},
        {"path": "native-gcc-support-0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-0.stdout", "sha256": "554ac4f3283aa67183de02f63d57798658c207014729de7481851407f6355a75", "size": 67},
        {"path": "native-gcc-support-1.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-1.stdout", "sha256": "3f213ce9e9b403d21aca86ba08f61458419300786c64ebd65ea002316b2803bb", "size": 66},
        {"path": "native-gcc-support-10.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-10.stdout", "sha256": "7306aebaebde40ce7ec0dc29b54c3ad611540edf77244f067f27be498a91c7e1", "size": 69},
        {"path": "native-gcc-support-11.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-11.stdout", "sha256": "3721ce8dff50c3d64de5c805411315676175aa8d6f1a73c60ff0dc23b56f3851", "size": 67},
        {"path": "native-gcc-support-12.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-12.stdout", "sha256": "a2089089ef24ef0381e316b87ac7c0a25209539c85f57f46883b0772b0d69cee", "size": 72},
        {"path": "native-gcc-support-13.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-13.stdout", "sha256": "ccf56e24f3f711b7fefedcb45a2bea9ec3cb2ab07977811b89cf61d7033dd161", "size": 67},
        {"path": "native-gcc-support-14.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-14.stdout", "sha256": "b2b1f65dce8bf858dd74dd11d3a75ef5e8325be9786aaad75b69030e6b69ead7", "size": 67},
        {"path": "native-gcc-support-2.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-2.stdout", "sha256": "367754b2451e40adeb0fef5c4010a2650ce66a86842dd92757e2442f8706da54", "size": 66},
        {"path": "native-gcc-support-3.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-3.stdout", "sha256": "0566eae03790430b0fc3a27bd7847a687f090069369c8c3eb2cd3f33a9adacec", "size": 45},
        {"path": "native-gcc-support-4.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-4.stdout", "sha256": "104853a79416b6612cf41a45bf7fa19ebeb81a6ed9b65fc00bd0307a698bdf75", "size": 43},
        {"path": "native-gcc-support-5.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-5.stdout", "sha256": "49e0ee3c95e74be54cf8cb48a3e08423726429a8edc38cb0a38018efb7e7e5b1", "size": 42},
        {"path": "native-gcc-support-6.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-6.stdout", "sha256": "ce82ddce3338aca45c5b51441853212e4ece6cd6d18f2f0a3f7055503e4d55a7", "size": 45},
        {"path": "native-gcc-support-7.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-7.stdout", "sha256": "44346845a2cb35dc1183f481c2b8b58898fede41bcfea0e24e15953394903114", "size": 45},
        {"path": "native-gcc-support-8.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-8.stdout", "sha256": "773e6ea40e190680d17bc141e6958f4ee73cedd14e8b66894388cc554ff29ef1", "size": 67},
        {"path": "native-gcc-support-9.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-support-9.stdout", "sha256": "badf21a6bcaa541e17b23d33bbe779fa1d7f04ceef62a4842777f90e2d693ba7", "size": 76},
        {"path": "native-gcc-version.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-gcc-version.stdout", "sha256": "bb6aade8c4ca40cae9cb1be8abe12377f651fccd82954af74ec61703b6608fc5", "size": 7},
        {"path": "native-package-10.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-10.stdout", "sha256": "e511fbe8cc3abe9c3a62dd53d6b100ead746a655199a3e4a2d974917d3e4592b", "size": 70},
        {"path": "native-package-14.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-14.stdout", "sha256": "70a0e64fdcef9cfbf5ca20d68b6c12d2be2bfde4f89e72803fa77403e846f193", "size": 91},
        {"path": "native-package-2.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-2.stdout", "sha256": "8869b8ba8020db04e229e6baa4f2110da6719d275dc30166778b88da09ff9cf9", "size": 95},
        {"path": "native-package-26.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-26.stdout", "sha256": "96f259bf445f93fd14b50047e46045ab232798bc3770bd56f6eec5ff5327a702", "size": 66},
        {"path": "native-package-27.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-27.stdout", "sha256": "67f8a4dad70880e873ea3464dbbfc27a6e7dd6bcedbac4527a9d0adbc5e108fc", "size": 87},
        {"path": "native-package-28.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-28.stdout", "sha256": "f2d0890fa73109b0bc2d1b661282b0dee93b34bd88928cf0a956a59664207af8", "size": 89},
        {"path": "native-package-3.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-3.stdout", "sha256": "1546103204496fb9f685fd4f1bb5a03828f2e20752671bac12ce5a9680a7eb59", "size": 89},
        {"path": "native-package-6.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-6.stdout", "sha256": "148f278086046bde3afde376bbd31e94753d0cc308f1fe68a79297d1b1f09f42", "size": 85},
        {"path": "native-package-7.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-7.stdout", "sha256": "60d7aa0ff0a074afff17587c5ace7a32191135a59b9443777ecf0e8dc5f1edf7", "size": 77},
        {"path": "native-package-8.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-8.stdout", "sha256": "a6862d1e918c0d29ef6f0e641de2b7aee63f95e2ca9c940643b3f072756536f0", "size": 81},
        {"path": "native-package-files-10.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-10.stdout", "sha256": "90aade04a970242e56e2f310f3d07b19155d47e69c987719928c5511fff6d830", "size": 21468},
        {"path": "native-package-files-14.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-14.stdout", "sha256": "497075b95afbfd7e88b4dedabfa5c5f8652cbb30e7b7bb89fbf189448cfa739a", "size": 9458},
        {"path": "native-package-files-2.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-2.stdout", "sha256": "7c01c08b17cb8c100d466b83d020485167747785f3cb4ada18d3e7a711d8e41b", "size": 1993},
        {"path": "native-package-files-26.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-26.stdout", "sha256": "6e43aaff6356615627dc6fc391701c2ff845c60974690d55fd2d3ee91201b4b7", "size": 12591},
        {"path": "native-package-files-27.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-27.stdout", "sha256": "15e8c970d00f276c85a094d7199d01eb9f5268fc59ca02b43ff8921b8f845ee0", "size": 221},
        {"path": "native-package-files-28.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-28.stdout", "sha256": "ce3b7c862096fbf71cca8ec8f0976bc0b9cb7bf0305790a2ea9b6e6b1868a03d", "size": 234},
        {"path": "native-package-files-3.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-3.stdout", "sha256": "b1512d05af328309493bdb7896faeae3da1e0cb52d33b76594927953bae5a71c", "size": 234},
        {"path": "native-package-files-6.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-6.stdout", "sha256": "d9d1f7f8716520f9adb11ca85d7122f1b9a7777d6242a3c353161781ba6de548", "size": 7612},
        {"path": "native-package-files-7.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-7.stdout", "sha256": "9651b116be0f1fc8075b64009a6d992bcf9ca0c09ea4cac9c500ccf585f49180", "size": 285},
        {"path": "native-package-files-8.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-files-8.stdout", "sha256": "800b6341f0adc7cbbe8f821b0df7b3ffba6e4129cc853b32f6dcc20f6cd2909f", "size": 1636},
        {"path": "native-package-recheck-0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-0.stdout", "sha256": "8869b8ba8020db04e229e6baa4f2110da6719d275dc30166778b88da09ff9cf9", "size": 95},
        {"path": "native-package-recheck-1.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-1.stdout", "sha256": "1546103204496fb9f685fd4f1bb5a03828f2e20752671bac12ce5a9680a7eb59", "size": 89},
        {"path": "native-package-recheck-2.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-2.stdout", "sha256": "148f278086046bde3afde376bbd31e94753d0cc308f1fe68a79297d1b1f09f42", "size": 85},
        {"path": "native-package-recheck-3.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-3.stdout", "sha256": "60d7aa0ff0a074afff17587c5ace7a32191135a59b9443777ecf0e8dc5f1edf7", "size": 77},
        {"path": "native-package-recheck-4.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-4.stdout", "sha256": "a6862d1e918c0d29ef6f0e641de2b7aee63f95e2ca9c940643b3f072756536f0", "size": 81},
        {"path": "native-package-recheck-5.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-5.stdout", "sha256": "e511fbe8cc3abe9c3a62dd53d6b100ead746a655199a3e4a2d974917d3e4592b", "size": 70},
        {"path": "native-package-recheck-6.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-6.stdout", "sha256": "70a0e64fdcef9cfbf5ca20d68b6c12d2be2bfde4f89e72803fa77403e846f193", "size": 91},
        {"path": "native-package-recheck-7.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-7.stdout", "sha256": "96f259bf445f93fd14b50047e46045ab232798bc3770bd56f6eec5ff5327a702", "size": 66},
        {"path": "native-package-recheck-8.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-8.stdout", "sha256": "67f8a4dad70880e873ea3464dbbfc27a6e7dd6bcedbac4527a9d0adbc5e108fc", "size": 87},
        {"path": "native-package-recheck-9.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "native-package-recheck-9.stdout", "sha256": "f2d0890fa73109b0bc2d1b661282b0dee93b34bd88928cf0a956a59664207af8", "size": 89},
        {"path": "package-members.txt", "sha256": "a9d84ade35a0afc95f993f04fff17011acb22296296a2b0d7dd5663ea0a4867d", "size": 441502},
        {"path": "publisher-F1-compile.stderr", "sha256": "82bbc036972f760a08ddf30faeb7df92f675530918b86b933a3e875d0a0b4f4e", "size": 186},
        {"path": "publisher-F1-compile.stdout", "sha256": "7733080ce54913606d0557a12d2844bed71458d3c1e791f213875374b88680ea", "size": 1518440},
        {"path": "publisher-compile.stderr", "sha256": "a5d6707f3f1e7f685a5cf14c9f9c7f849c42809d7e5ae6b9937a5777ac734b18", "size": 1363},
        {"path": "publisher-compile.stdout", "sha256": "72a7e93d82d86602afeb47daae1a7685524b54ef7bbd605544858809d00ea062", "size": 1518486},
        {"path": "result.json", "sha256": "592921fb21b31988733bd54091153a11ef90046988a292970a14e210a6f28f9f", "size": 36503},
        {"path": "root-lifecycle.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "root-lifecycle.stdout", "sha256": "668e34f3b738ae5ca8af5d91743e6fe1d236c0c875a0b863df625e917110d5bf", "size": 109},
        {"path": "runtime-inputs.json", "sha256": "a1a9561db3def48996e1ff84db413189c2d1f4ec17b143b476ceea5b4506391f", "size": 6822},
        {"path": "rust-acquire.stderr", "sha256": "3c6a4fcab6187ee7881c52ec7ee91a2d4f0003c665973b190ec0fde5e0985c35", "size": 236},
        {"path": "rust-acquire.stdout", "sha256": "3d00ee031f9ca6c5c559d3cb02f8765b38c2df6afc15bb6f80de52687f2e6909", "size": 84},
        {"path": "rust-version.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "rust-version.stdout", "sha256": "3975d062e234a9f3921955bf6ae5b90f5819df94fa825d057f76b34a35ed0f4d", "size": 196},
        {"path": "rustc-selection.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "rustc-selection.stdout", "sha256": "fcf5016fe6903bffcfb485ee743846bba209964a26af3dfa2757d4afe1ec5a31", "size": 132},
        {"path": "source-tree.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "source-tree.stdout", "sha256": "5184f7a4bbf6465a38c7caa9fa4cabf97b145fb451e4a605deca6eebc19becdf", "size": 41},
        {"path": "source.json", "sha256": "19fbf952d98c9a0efa8fcdf2deeb48000124a9acf000669d919f3388c9556784", "size": 794},
        {"path": "stage-F1.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "stage-F1.stdout", "sha256": "8d7084fca43e9ef3d3ba261fdf5e868137d7d12ca7090e86d7dd2ad560f4afe0", "size": 167},
        {"path": "stage-P0.stderr", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": 0},
        {"path": "stage-P0.stdout", "sha256": "9f61d09db3ae0108eaf7981c62a80b67e95c008acab908bc607c3a55c63aabc0", "size": 167},
        {"path": "version-signature.txt", "sha256": "df40e94048e7d33fe5eb703e6adf4f644a283079fd7acaf8d47d7447cdc5d7ea", "size": 36},
    ],
}
WORKFLOW = ".github/workflows/desktop-ubuntu-publication.yml"
FEATURES = ["ubuntu-runtime-publisher"]
TARGET = "x86_64-unknown-linux-gnu"
PREFIX = "runtime_publication::tests::"
TESTS = tuple(sorted(PREFIX + name for name in (
    "release_inputs_are_fixed_and_lowercase", "root_status_requires_all_initial_root_ids",
    "complete_membership_requires_exact_manifest_roster",
    "helper_fresh_copy_has_independent_inode_and_bytes", "helper_source_size_digest_and_readback_refuse",
    "helper_noreplace_preserves_existing_names", "helper_lost_close_receipt_blocks_publication",
    "helper_stage_sync_failure_prevents_rename", "helper_parent_sync_failure_preserves_published_name",
    "helper_extra_destination_member_is_rejected", "helper_source_directory_drift_is_rejected",
)))
LOG_LIMIT = 2 << 20
LOG_TOTAL = 64 << 20
MAX_BINARY = 512 << 20
MAX_DEB = 512 << 20
KERNEL_SELECTOR = "installed_runtime::pure_tests::kernel_scope_is_reviewed_ubuntu"
F1_MANIFEST_SHA256 = "1270d1d7d9427fff260bb1e79f51c1c3c14145651db87014b0ee9d08d601c112"
FIXTURE_SOURCE = b"fn main() { std::process::exit(78); }\n"
NOTICE_INPUTS_SHA256 = "88405397949e3528141d0b9adb5246b72e4d052e1e802df8855c8bc8c8adbe6c"
SONAME_PACKAGES = {name: "libc6:amd64" for name in (
    "libc.so.6", "ld-linux-x86-64.so.2", "libm.so.6", "libmvec.so.1", "libdl.so.2",
    "libpthread.so.0", "librt.so.1", "libutil.so.1")}
SONAME_PACKAGES["libgcc_s.so.1"] = "libgcc-s1:amd64"
COMMON_LICENSE_PATTERN = rb"/usr/share/common-licenses/([A-Za-z0-9][A-Za-z0-9.+_\-]*)"
COMMON_LICENSES = {"GPL", "GPL-1", "GPL-2", "GPL-3", "LGPL", "LGPL-2", "LGPL-2.1", "LGPL-3",
                   "GFDL", "GFDL-1.2", "GFDL-1.3", "Apache-2.0", "Artistic", "BSD", "CC0-1.0", "MPL-1.1", "MPL-2.0"}
RUNTIME_ELF = {"python/bin/python3": (None, "$ORIGIN/../lib"),
               "python/lib/libssl.so.3": ("libssl.so.3", "$ORIGIN"),
               "python/lib/libcrypto.so.3": ("libcrypto.so.3", "$ORIGIN")}


def route(env):
    installed = env.get("MRK_INSTALLED_CASE")
    shell = env.get("MRK_INSTALLED_SHELL_CASE")
    if shell is not None:
        fixed = (installed is None and env.get("GITHUB_REF") == SHELL_REF and shell in {"compile", "observe"}
                 and env.get("GITHUB_JOB") == "compile")
    else:
        fixed = (env.get("GITHUB_REF") == INSTALLED_REF and installed in INSTALLED_CASES | {"compile"}
                 if installed is not None else env.get("GITHUB_REF") == REF)
    D.need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
           and env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
           and env.get("GITHUB_EVENT_NAME") == "push" and fixed
           and env.get("MRK_UBUNTU_PUBLICATION_VERIFY") == "1", "Wrong fixed publisher verification route")
    sha = env.get("GITHUB_SHA", "")
    D.need(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
           and env.get("MRK_PUSH_EVENT_AFTER") == sha, "Publisher event source differs")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        D.need(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")) is not None, "Invalid original run identity")
    D.need(env.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit", "Different repository")
    return sha


def compile_argv(cargo, source, target, *, library, candidate=False):
    D.need(not candidate or library, "The installed candidate is only the feature-off libtest")
    return [cargo, "test" if library else "build", "--locked", "--offline", "--jobs", "1",
            "--no-default-features", *([] if candidate else ["--features", FEATURES[0]]), "--target", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml"),
            "--target-dir", str(target), *( ["--lib", "--no-run"] if library else ["--release", "--bin", "mrk-runtime-publish"] ),
            "--message-format=json"]


def compiled_artifact(raw, source, target_root, *, library, candidate=False):
    """Select only an original fresh Cargo result for this fixed profile."""
    D.need(not candidate or library, "The installed candidate is only the feature-off libtest")
    D.need(type(raw) is bytes and 0 < len(raw) <= LOG_LIMIT, "Compiler message bound")
    executable, finished = None, False
    for line in raw.splitlines():
        D.need(not finished, "Compiler data follows its final result")
        row = C.bounded_json(line, 1 << 20)
        D.need(type(row) is dict and type(row.get("reason")) is str, "Invalid original compiler message")
        if row["reason"] == "compiler-artifact" and row.get("executable") is not None:
            kind, name, filename = (("lib", "mobile_release_desktop", "lib.rs") if library
                                    else ("bin", "mrk-runtime-publish", "bin/runtime_publish.rs"))
            target, profile = row.get("target"), row.get("profile")
            D.need(executable is None and type(target) is dict and target.get("kind") == [kind]
                   and target.get("name") == name and target.get("src_path") == str(source / "desktop/src-tauri/src" / filename)
                   and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                   and row.get("features") == ([] if candidate else FEATURES) and row.get("fresh") is False
                   and type(profile) is dict and profile.get("test") is library
                   and profile.get("debug_assertions") is library
                   and profile.get("opt_level") == ("0" if library else "3"), "Different publisher compiler profile")
            value = row["executable"]
            if library:
                executable = C.github_executable_path(value, target_root=target_root)
            else:
                D.need(value == str(target_root / TARGET / "release/mrk-runtime-publish"), "Publisher binary path differs")
                executable = Path(value)
        elif row["reason"] == "build-finished":
            D.need(row.get("success") is True, "Original publisher compiler failed")
            finished = True
    D.need(finished and executable is not None, "Compiler did not yield exactly one fresh artifact")
    return executable


def shell_compile_argv(cargo, source, target):
    """One build, two selected executables, shared dependencies; never cargo test."""
    return [cargo, "build", "--locked", "--offline", "--jobs", "1", "--no-default-features",
            "--features", SHELL_FEATURE_ARG, "--target", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml"),
            "--target-dir", str(target), "--profile", "dev", "--bin", SHELL_EXPORTS["normal"],
            "--test", SHELL_EXPORTS["observer"], "--message-format=json"]


def shell_compiled_artifacts(raw, source, target_root):
    """Select the normal main and separate harness-free observer, never libtest.

    Cargo's profile.test field is not the target's manifest harness setting.
    The observer is selected by its explicit test target/command/source, with
    harness=false independently admitted from Cargo.toml. Retain the original
    boolean rather than guessing its value for cargo build --test.
    """
    D.need(type(raw) is bytes and 0 < len(raw) <= SHELL_COMPILE_LIMIT, "Shell compiler message bound")
    artifacts, units, finished = {}, [], False
    expected = {"normal": (["bin"], SHELL_EXPORTS["normal"], "src/main.rs"),
                "observer": (["test"], SHELL_EXPORTS["observer"], "tests/installed_shell_observation.rs")}
    for line in raw.splitlines():
        D.need(not finished, "Shell compiler data follows its final result")
        row = C.bounded_json(line, 2 << 20)
        D.need(type(row) is dict and row.get("reason") in {
            "compiler-artifact", "build-script-executed", "compiler-message", "build-finished"},
            "Unknown original shell compiler message")
        if row["reason"] == "build-finished":
            D.need(row.get("success") is True, "Original shell compiler failed")
            finished = True
        elif row["reason"] == "compiler-artifact":
            D.need(type(row.get("package_id")) is str and type(row.get("features")) is list
                   and all(type(value) is str for value in row["features"])
                   and type(row.get("fresh")) is bool and type(row.get("target")) is dict
                   and type(row.get("profile")) is dict, "Shell compiler unit metadata differs")
            units.append({key: row[key] for key in ("package_id", "features", "fresh", "target", "profile")})
            D.need(len(units) <= 2048, "Shell compiler unit count bound")
            if row.get("executable") is None:
                continue
            target, profile = row.get("target"), row.get("profile")
            D.need(type(target) is dict and type(profile) is dict, "Shell executable target/profile missing")
            matches = [role for role, (kind, name, relative) in expected.items()
                       if target.get("kind") == kind and target.get("name") == name
                       and target.get("src_path") == str(source / "desktop/src-tauri" / relative)]
            D.need(len(matches) == 1, "Unselected shell executable in original compiler output")
            role = matches[0]
            D.need(role not in artifacts and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                   and row["features"] == SHELL_FEATURES and row["fresh"] is False
                   and profile.get("opt_level") == "0" and profile.get("debug_assertions") is True
                   and type(profile.get("test")) is bool and (role != "normal" or profile["test"] is False),
                   "Different/freshness-lost shell compiler profile")
            value = row["executable"]
            D.need(type(value) is str and type(row.get("filenames")) is list and value in row["filenames"],
                   "Shell executable is absent from its original output roster")
            path = Path(value)
            if role == "normal":
                D.need(path == target_root / TARGET / "debug" / SHELL_EXPORTS[role], "Normal shell output path differs")
            else:
                D.need(path.parent == target_root / TARGET / "debug/deps"
                       and re.fullmatch(r"installed_shell_observation-[0-9a-f]{16}", path.name) is not None,
                       "Harness-free shell observer output path differs")
            artifacts[role] = {"path": value, "packageId": row["package_id"], "target": target,
                               "profile": profile, "features": row["features"]}
    D.need(finished and set(artifacts) == set(SHELL_EXPORTS), "Shell compiler did not yield both fresh selected outputs")
    return artifacts, units


def test_result(stdout, stderr):
    D.need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) <= 2 << 20
           and stderr == b"", "Publisher test capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    D.need(len(lines) == len(TESTS) + 2 and lines[0] == f"running {len(TESTS)} tests"
           and lines[1:-1] == [f"test {name} ... ok" for name in TESTS]
           and re.fullmatch(r"test result: ok\. 11 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[-1]) is not None,
           "Exact publisher test roster did not pass once")


def exact_test_result(stdout, stderr, name):
    """A settled singleton result, never zero/partial/extra tests-as-success."""
    D.need(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_:]+", name) is not None
           and type(stdout) is bytes and 0 < len(stdout) <= 2 << 20 and stderr == b"",
           "Exact singleton test capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    D.need(len(lines) == 3 and lines[:2] == ["running 1 test", f"test {name} ... ok"]
           and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[2]) is not None,
           "Exact singleton test did not pass once")


def elf_dependencies(raw, *, runtime_path=None, shell=False, shell_path=None, shell_provider=False):
    """Bounded ELF DATA, including required/exported symbol-version labels.

    No binary, loader, ldd or readelf execution. The caller binds the actual
    source/output and native package files; labels alone never admit a host.
    """
    D.need(type(raw) is bytes and 64 <= len(raw) <= MAX_BINARY, "ELF byte bound")
    D.need(runtime_path is None or runtime_path in RUNTIME_ELF, "Only the fixed A ELF profile has a private RUNPATH")
    D.need(type(shell) is bool and not (shell and runtime_path is not None), "Separate shell/A ELF profiles required")
    D.need(type(shell_provider) is bool and (not shell_provider or shell), "Provider role requires the shell ELF profile")
    D.need(shell_path is None or shell and type(shell_path) is str and Path(shell_path).is_absolute()
           and ".." not in Path(shell_path).parts, "Only the isolated shell profile has a requester path")

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        D.need(type(offset) is int and 0 <= offset <= len(raw) - size, "ELF record extent")
        return struct.unpack_from(fmt, raw, offset)

    ident, kind, machine, version, _, phoff, _, _, ehsize, phsize, phnum, _, _, _ = unpack("<16sHHIQQQIHHHHHH", 0)
    D.need(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in (2, 3) and machine == 62
           and version == 1 and ehsize == 64 and phsize == 56 and 0 < phnum <= 128,
           "Expected bounded ELF64 little-endian x86_64")
    D.need(not shell_provider or kind == 3, "Shell provider must be an ET_DYN shared object")
    headers = [unpack("<IIQQQQQQ", phoff + i * phsize) for i in range(phnum)]
    for p in headers:
        D.need(p[2] <= len(raw) and p[5] <= len(raw) - p[2]
               and (p[0] != 1 or p[5] <= p[6]), "ELF segment extent")

    def address(value, length):
        candidates = [p[2] + value - p[3] for p in headers if p[0] == 1 and p[3] <= value
                      and length <= p[5] and value - p[3] <= p[5] - length]
        D.need(len(candidates) == 1, "ELF pointer is not uniquely file-backed")
        return candidates[0]

    interpreters, dynamics = [p for p in headers if p[0] == 3], [p for p in headers if p[0] == 2]
    D.need(len(interpreters) <= 1 and len(dynamics) == 1, "ELF interpreter/dynamic count")
    interpreter = None
    if interpreters:
        p = interpreters[0]
        D.need(1 < p[5] <= 4096, "ELF interpreter bound")
        value = raw[p[2]:p[2] + p[5]]
        D.need(value.endswith(b"\0") and b"\0" not in value[:-1], "ELF interpreter termination")
        interpreter = value[:-1].decode("ascii")
        D.need(interpreter == "/lib64/ld-linux-x86-64.so.2", "Unreviewed ELF interpreter")
    dynamic = dynamics[0]
    D.need(0 < dynamic[5] <= 65536 and dynamic[5] % 16 == 0, "ELF dynamic bound")
    tags, finished = {}, False
    for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = unpack("<qQ", offset)
        if tag == 0:
            finished = True
            break
        D.need(tag not in {15, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}
               and (tag != 29 or runtime_path is not None or shell_path in SHELL_RUNPATHS),
               "ELF search/audit/filter override refused")
        tags.setdefault(tag, []).append(value)
    D.need(finished, "Unterminated ELF dynamic table")

    def single(tag, optional=False):
        values = tags.get(tag, [])
        D.need(len(values) == 1 or optional and not values, "ELF singleton dynamic tag")
        return values[0] if values else None

    if shell_provider:
        # PT_INTERP may also be present on a dual-use shared library. Loading
        # it as DT_NEEDED does not execute that entry. Check its actual DSO
        # role instead; providers never become approved subprocess programs.
        flags = single(0x6FFFFFFB, True)  # DT_FLAGS_1
        D.need(flags is None or flags & 0x08000000 == 0, "Shell provider must not be a PIE executable")

    size = single(10)
    D.need(0 < size <= (16 << 20 if shell else 2 << 20), "ELF string table bound")
    offset = address(single(5), size)
    strings = raw[offset:offset + size]

    def string(index):
        D.need(0 <= index < size, "ELF string index")
        end = strings.find(b"\0", index)
        D.need(index <= end <= index + 4096, "ELF string termination/bound")
        return strings[index:end].decode("ascii")

    needed = [string(value) for value in tags.get(1, [])]
    allowed = set(SONAME_PACKAGES) | ({"libssl.so.3", "libcrypto.so.3"} if runtime_path is not None else set())
    D.need(len(needed) <= (128 if shell else 32) and len(set(needed)) == len(needed)
           and all((re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]{0,191}", name) is not None and ".so" in name)
                   if shell else name in allowed for name in needed), "Unreviewed/duplicate native ELF dependency")
    requirements, definitions = {}, []
    pointer, count = single(0x6FFFFFFE, True), single(0x6FFFFFFF, True)
    D.need((pointer is None) == (count is None), "Incomplete ELF version-needs")
    if pointer is not None:
        D.need(0 < count <= (128 if shell else 32), "ELF version-need count")
        seen = set()
        for i in range(count):
            D.need(pointer not in seen, "ELF version-need cycle")
            seen.add(pointer)
            ver, n, fileidx, aux, nxt = unpack("<HHIII", address(pointer, 16))
            name = string(fileidx)
            D.need(ver == 1 and 0 < n <= 512 and aux >= 16 and name in needed and name not in requirements,
                   "ELF version-need record")
            values, at, auxseen = [], pointer + aux, set()
            for j in range(n):
                D.need(at not in auxseen, "ELF version auxiliary cycle")
                auxseen.add(at)
                _, _, _, index, step = unpack("<IHHII", address(at, 16))
                values.append(string(index))
                D.need((step == 0) == (j == n - 1) and (step == 0 or step >= 16), "ELF version auxiliary chain")
                at += step
            requirements[name] = values
            D.need((nxt == 0) == (i == count - 1) and (nxt == 0 or nxt >= 16), "ELF version-need chain")
            pointer += nxt
    pointer, count = single(0x6FFFFFFC, True), single(0x6FFFFFFD, True)
    D.need((pointer is None) == (count is None), "Incomplete ELF version definitions")
    if pointer is not None:
        D.need(0 < count <= 512, "ELF version-definition count")
        seen = set()
        for i in range(count):
            D.need(pointer not in seen, "ELF version-definition cycle")
            seen.add(pointer)
            ver, _, _, n, _, aux, nxt = unpack("<HHHHIII", address(pointer, 20))
            D.need(ver == 1 and 0 < n <= 32 and aux >= 20, "ELF version-definition record")
            at = pointer + aux
            for j in range(n):
                index, step = unpack("<II", address(at, 8))
                value = string(index)
                if j == 0:
                    definitions.append(value)
                D.need((step == 0) == (j == n - 1) and (step == 0 or step >= 8), "ELF definition auxiliary chain")
                at += step
            D.need((nxt == 0) == (i == count - 1) and (nxt == 0 or nxt >= 20), "ELF version-definition chain")
            pointer += nxt
    soname = single(14, True)
    result = {"interpreter": interpreter, "needed": needed, "versionNeeds": requirements,
              "versionDefinitions": definitions, "soname": string(soname) if soname is not None else None}
    if runtime_path is not None:
        runpath = single(29)
        D.need((result["soname"], string(runpath)) == RUNTIME_ELF[runtime_path]
               and (interpreter == "/lib64/ld-linux-x86-64.so.2" if runtime_path == "python/bin/python3"
                    else interpreter is None), "Actual A interpreter/SONAME/private RUNPATH differs")
        result["runpath"] = string(runpath)
    elif shell_path in SHELL_RUNPATHS:
        runpath = single(29)
        D.need((result["soname"], string(runpath)) == SHELL_RUNPATHS[shell_path]
               and interpreter is None, "Fixed shell requester/SONAME/private RUNPATH differs")
        result["runpath"] = string(runpath)
    return result


def shell_provider_path(requester, runpath, name):
    """Resolve one actual shell edge, never make a private directory global."""
    D.need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]{0,191}", name) is not None
           and ".so" in name, "Shell provider name differs")
    D.need(runpath is None or requester in SHELL_RUNPATHS and SHELL_RUNPATHS[requester][1] == runpath,
           "Shell dependency has an unadmitted requester search path")
    private = SHELL_PRIVATE_PROVIDERS.get(name)
    D.need(private is None or runpath == private, "Private shell provider is not authorized by this requester")
    return str(Path(private or SHELL_LIBRARY_ROOT) / name)


def shell_elf_record(raw, *, role, selected=None):
    """Bounded diagnosis names only a fixed public OS input or output role."""
    D.need(role in {"program", "module", "provider", "normal", "observer"}
           and (selected is None or type(selected) is str and len(selected) <= 240
                and selected.startswith((SHELL_LIBRARY_ROOT + "/", "/usr/bin/", "/bin/"))),
           "Shell ELF diagnostic input is not a fixed public role/path")
    try:
        return elf_dependencies(raw, shell=True, shell_path=selected, shell_provider=role == "provider")
    except Exception as error:
        label = role + (" " + selected if selected is not None else "")
        raise D.Refused(("Shell ELF " + label + ": " + failure_reason(error))[:500]) from error


def deb_readback(path, data_rows, control_rows):
    """Exact uncompressed .deb ar/tar DATA readback, never extraction/install."""
    raw = D.read(path, MAX_DEB)
    D.need(raw.startswith(b"!<arch>\n"), "Debian ar signature differs")
    offset, totals = 8, {}
    for wanted, rows in (("debian-binary", None), ("control.tar", control_rows), ("data.tar", data_rows)):
        D.need(offset + 60 <= len(raw), "Truncated Debian ar header")
        header = raw[offset:offset + 60]
        D.need(header[58:] == b"`\n", "Debian ar header terminator")
        name = header[:16].decode("ascii").rstrip(" ").removesuffix("/")
        D.need(name == wanted and re.fullmatch(rb"[0-9]+ *", header[16:28]) is not None
               and header[28:34].strip() == header[34:40].strip() == b"0"
               and header[40:48].strip() == b"100644"
               and re.fullmatch(rb"[0-9]+ *", header[48:58]) is not None, "Debian ar name/owner/mode differs")
        size = int(header[48:58])
        offset += 60
        D.need(0 <= size <= len(raw) - offset, "Debian ar member extent")
        body = raw[offset:offset + size]
        offset += size
        if size & 1:
            D.need(raw[offset:offset + 1] == b"\n", "Debian ar padding differs")
            offset += 1
        if rows is None:
            D.need(body == b"2.0\n", "Debian format version differs")
            continue
        D.need(type(rows) is dict and 0 < len(rows) <= 32768 and len(body) % 512 == 0,
               "Debian expected roster/tar bound")
        seen, end, files, bytes_ = set(), 0, 0, 0
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as archive:
            for member in archive:
                D.need(member.offset == end, "Hidden Debian tar record")
                if member.offset_data != end + 512:
                    # GNU tar needs one long-name DATA header for the fixed
                    # manifest-addressed paths. It is not a filesystem link.
                    # Account for it explicitly; never let tarfile hide PAX,
                    # long-link, sparse or chained extension records.
                    extension = tarfile.TarInfo.frombuf(body[end:end + 512], "ascii", "strict")
                    D.need(extension.type == tarfile.GNUTYPE_LONGNAME and extension.name == "././@LongLink"
                           and extension.uid == extension.gid == 0 and extension.linkname == ""
                           and 101 <= extension.size <= 514, "Unreviewed Debian tar extension")
                    name_end = end + 512 + extension.size
                    header_at = (name_end + 511) // 512 * 512
                    extended_name = body[end + 512:name_end]
                    D.need(len(extended_name) == extension.size and extended_name.endswith(b"\0")
                           and b"\0" not in extended_name[:-1]
                           and extended_name[:-1].decode("ascii").removesuffix("/") == member.name.removesuffix("/")
                           and not body[name_end:header_at].strip(b"\0")
                           and member.offset_data == header_at + 512, "Debian tar long-name body/extent differs")
                D.need(member.name == "." or member.name.startswith("./"), "Noncanonical Debian tar name")
                name = member.name[2:] if member.name.startswith("./") else "."
                name = name.removesuffix("/") or "."
                if name != ".":
                    D.relative(name)
                D.need(name not in seen and name in rows and name.split("/", 1)[0] not in {"opt", "var"}
                       and member.uid == member.gid == 0 and member.uname in ("", "root")
                       and member.gname in ("", "root") and not member.pax_headers and not member.issparse()
                       and member.linkname == "", "Debian tar member/owner/extension differs")
                row = rows[name]
                D.need(member.mode == row["mode"], "Debian tar mode differs")
                seen.add(name)
                if row["type"] == "directory":
                    D.need(member.type == tarfile.DIRTYPE and member.size == 0, "Debian directory type differs")
                else:
                    D.need(row["type"] == "file" and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                           and member.size == row["size"], "Debian file type/size differs")
                    D.sha(row["sha256"])
                    digest, count = hashlib.sha256(), 0
                    with archive.extractfile(member) as stream:
                        while chunk := stream.read(64 << 10):
                            count += len(chunk)
                            D.need(count <= row["size"], "Debian file grew")
                            digest.update(chunk)
                    D.need(count == row["size"] and digest.hexdigest() == row["sha256"], "Debian file body differs")
                    files += 1
                    bytes_ += count
                member_end = member.offset_data + member.size
                padded = (member_end + 511) // 512 * 512
                D.need(not body[member_end:padded].strip(b"\0"), "Nonzero Debian tar body padding")
                end = max(end, padded)
                D.need(len(seen) <= len(rows), "Debian tar member bound")
        D.need(seen == set(rows) and len(body) - end >= 1024 and not body[end:].strip(b"\0"),
               "Debian tar missing members or hidden/truncated ending")
        totals[wanted] = {"entries": len(seen), "files": files, "bytes": bytes_}
    D.need(offset == len(raw), "Extra Debian ar member/trailing bytes")
    return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), **totals}


def directory_identity(path):
    D.directory(path)
    value = path.lstat()
    D.need(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700, "Private task directory changed")
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def artifact_record(path, *, copy_to=None):
    """Cargo may hardlink its own outputs. This is NOT runtime-file admission.

    Keep the original identity/count stable while reading; an exported copy is
    a fresh single-link file whose bytes are independently read back.
    """
    D.directory(path.parent)
    before = path.lstat()
    D.need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1 and before.st_uid == os.geteuid()
           and before.st_mode & 0o7022 == 0 and before.st_mode & stat.S_IXUSR
           and 0 < before.st_size <= MAX_BINARY, "Unexpected compiler output identity")
    identity = (*D.state(before), before.st_uid, before.st_gid)
    original = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        stream = os.fdopen(original, "rb")
    except BaseException:
        os.close(original)
        raise
    writer = None
    try:
        with stream as source:
            opened = os.fstat(source.fileno())
            D.need((*D.state(opened), opened.st_uid, opened.st_gid) == identity, "Compiler output changed before read")
            if copy_to is not None:
                writer = copy_to.open("xb")
            digest, size = hashlib.sha256(), 0
            for block in iter(lambda: source.read(64 << 10), b""):
                size += len(block)
                D.need(size <= before.st_size, "Compiler output grew")
                digest.update(block)
                if writer is not None:
                    D.need(writer.write(block) == len(block), "Short compiler output copy")
            D.need(size == before.st_size and D.state(os.fstat(source.fileno())) == D.state(before), "Compiler output changed")
            if writer is not None:
                writer.flush()
                os.fchmod(writer.fileno(), 0o555)
                os.fsync(writer.fileno())
    finally:
        if writer is not None:
            writer.close()
    after = path.lstat()
    D.need((*D.state(after), after.st_uid, after.st_gid) == identity, "Compiler output identity changed after close")
    result = {"path": str(path), "size": size, "sha256": digest.hexdigest(), "identity": list(identity)}
    if copy_to is not None:
        D.bound(copy_to, {"path": copy_to.name, "size": size, "sha256": result["sha256"]})
    return result


class Check:
    def __init__(self, root, owner, *, deadline=None):
        self.root, self.owner = root, owner
        self.end = time.monotonic() + 1200 if deadline is None else deadline
        self.retained = 0
        self.phase = "admission"
        self.commands = []
        self.failed = False

    def command(self, label, argv, env, cwd, *, timeout=600, codes=(0,), limit=LOG_LIMIT):
        D.need(not self.failed, "Prior command failed; no further launch")
        self.phase = label
        self.failed = True
        remaining = min(timeout, int(self.end - time.monotonic()))
        D.need(remaining >= 1, "Common publisher-check endpoint expired")
        print("Publisher check: " + label, flush=True)
        result = self.owner(argv, environ=env, cwd=cwd, timeout=remaining, capture=True, text=False, output_limit=limit)
        D.need(type(result) is subprocess.CompletedProcess and result.args == argv
               and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes,
               "Original command result incomplete")
        size = len(result.stdout) + len(result.stderr)
        D.need(size <= limit and self.retained + size <= LOG_TOTAL, "Original command capture bound")
        self.retained += size
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            D.write(self.root / "public" / (label + "." + suffix), raw)
        self.commands.append({"phase": label, "argv": argv, "exitCode": result.returncode,
                              "timeoutSeconds": remaining, "ordinaryOwnerReturned": True})
        on_time = time.monotonic() < self.end
        D.need(result.returncode in codes and on_time, "Original command failed or finished late: " + label
               + f" (exitCode={result.returncode}, endpointExpired={not on_time})")
        self.failed = False
        return result


def failure_reason(error):
    """Only source-labelled invariant text; never arbitrary exception bodies."""
    if (type(error) in (D.Refused, C.CheckFailure)
            or type(error).__module__.startswith(("_publisher_", "_deb_"))
            and type(error).__name__ in {"Refused", "PreparationError", "SmokeRefused"}):
        reason = str(error)
        if 0 < len(reason) <= 512 and all(32 <= ord(character) < 127 for character in reason):
            return reason
    if isinstance(error, OSError):
        return type(error).__name__ + " errno=" + str(error.errno)
    return type(error).__name__


def retain_failure(root, phase, commands, error):
    # Diagnostic retention must not replace the original failure or launch any
    # follow-up process. Never inspect a possibly-live privileged service tree.
    reason = failure_reason(error)
    print("Publisher check refused in " + phase + ": " + reason, file=sys.stderr, flush=True)
    try:
        directory_identity(root)
        directory_identity(root / "public")
        D.write(root / "public/failure.json", D.canonical({"phase": phase, "reason": reason, "commands": commands,
                "qualified": False, "partialOutputsMayRemain": True, "cleanupEstablished": False}))
    except Exception as diagnostic_error:
        print("Publisher failure evidence could not be retained: " + failure_reason(diagnostic_error), file=sys.stderr, flush=True)


def hosted_paths():
    sha = route(os.environ)
    C.conventional_host(D)
    uids, gids = os.getresuid(), os.getresgid()
    D.need(uids[0] != 0 and gids[0] != 0 and len(set(uids)) == len(set(gids)) == 1,
           "One genuine nonroot runner identity required")
    source, temporary = Path(os.environ["GITHUB_WORKSPACE"]), Path(os.environ["RUNNER_TEMP"])
    for path in (source, temporary):
        D.directory(path)
        D.need(path.resolve(strict=True) == path, "Noncanonical hosted directory")
    D.need(source == SOURCE, "Publisher checkout source differs")
    root = temporary / ("mrk-desktop-ubuntu-publisher-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
    if "MRK_INSTALLED_SHELL_CASE" in os.environ:
        # Two original tasks on one VM, not renewal/reuse of the compiler root.
        root = root.with_name(root.name + "-" + os.environ["MRK_INSTALLED_SHELL_CASE"])
    return sha, source, temporary, root


def preparation_route():
    """Bind the fixed same-job role in each shell preparation, not a caller path."""
    return ({"shellCase": os.environ["MRK_INSTALLED_SHELL_CASE"], "job": os.environ["GITHUB_JOB"]}
            if "MRK_INSTALLED_SHELL_CASE" in os.environ else {})


def prepare():
    """Create the one private root/endpoint BEFORE the fixed A download action."""
    started = time.monotonic()
    sha, source, _, root = hosted_paths()
    os.umask(0o077)
    root.mkdir(mode=0o700)
    try:
        (root / "public").mkdir(mode=0o700)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("root=" + str(root) + "\n")
        for name in ("work", "cases"):
            (root / name).mkdir(mode=0o700)
        for name in ("home", "tmp", "cargo", "rustup", "target"):
            (root / "work" / name).mkdir(mode=0o700)
        D.write(root / "work/gitconfig-empty", b"")
        deadline = repr(started + 1200)
        row = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "source": str(source), "root": str(root), "deadline": deadline,
               "runnerUid": os.getuid(), "runnerGid": os.getgid(),
               "rootIdentity": list(directory_identity(root)), "workIdentity": list(directory_identity(root / "work")),
               **preparation_route()}
        pin = D.write(root / "preparation.json", D.canonical(row))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("preparation_sha256=" + pin["sha256"] + "\ndeadline=" + deadline + "\n")
    except BaseException as error:
        retain_failure(root, "prepare", [], error)
        raise


def resumed_preparation():
    sha, source, temporary, root = hosted_paths()
    D.need(os.environ.get("MRK_UBUNTU_PUBLICATION_ROOT") == str(root), "Original private root differs")
    raw = D.read(root / "preparation.json", 16384)
    D.need(hashlib.sha256(raw).hexdigest() == D.sha(os.environ.get("MRK_UBUNTU_PUBLICATION_PREPARATION_SHA256")),
           "Original preparation pin differs")
    row = D.decode(raw, 16384)
    expected = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                "source": str(source), "root": str(root), "deadline": os.environ.get("MRK_UBUNTU_PUBLICATION_DEADLINE"),
                "runnerUid": os.getuid(), "runnerGid": os.getgid(),
                "rootIdentity": list(directory_identity(root)), "workIdentity": list(directory_identity(root / "work")),
                **preparation_route()}
    D.need(D.same(row, expected) and type(row["deadline"]) is str
           and re.fullmatch(r"[0-9]+\.[0-9]+", row["deadline"]) is not None, "Original preparation binding changed")
    deadline = float(row["deadline"])
    D.need(math.isfinite(deadline) and 0 < deadline - time.monotonic() <= 1200,
           "Original lifecycle endpoint expired/invalid; never renew it")
    return sha, source, temporary, root, deadline


def protected_host_file(path, limit=MAX_BINARY):
    """Root-owned OS DATA, resolving only protected original link ancestry."""
    path = Path(path)
    D.need(path.is_absolute() and ".." not in path.parts, "Absolute native OS input required")
    links, ancestry, pending, resolved = [], {}, list(path.parts[1:]), Path("/")
    root_stat = resolved.lstat()
    D.need(stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == root_stat.st_gid == 0
           and not root_stat.st_mode & 0o7022, "Unprotected native OS root")
    ancestry[str(resolved)] = [root_stat.st_dev, root_stat.st_ino, root_stat.st_mode, root_stat.st_uid, root_stat.st_gid]
    steps = 0
    while pending:
        steps += 1
        D.need(steps <= 256, "Native OS input link/ancestry bound")
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        st = candidate.lstat()
        D.need(st.st_uid == st.st_gid == 0, "Native OS input has a nonroot owner")
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(candidate)
            D.need(len(links) < 40 and 0 < len(target) <= 4096 and D.state(candidate.lstat()) == D.state(st),
                   "Native OS input link changed/exceeded bound")
            links.append([str(candidate), list(D.state(st)), target])
            target = Path(target)
            if target.is_absolute():
                resolved, parts = Path("/"), target.parts[1:]
            else:
                parts = target.parts
            pending = [*parts, *pending]
        else:
            D.need(not st.st_mode & 0o7022 and (stat.S_ISDIR(st.st_mode) if pending else stat.S_ISREG(st.st_mode)),
                   "Native OS input has nonordinary/writable/special ancestry")
            resolved = candidate
            if pending:
                ancestry[str(candidate)] = [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid]
    D.need(path.resolve(strict=True) == resolved, "Resolved native OS input differs")
    st = resolved.lstat()
    D.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "Native OS input is not an ordinary file")
    row = D.file_record(resolved, limit)
    for name, expected in ancestry.items():
        observed = Path(name).lstat()
        D.need([observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid] == expected,
               "Native OS ancestry changed while reading")
    for name, expected, target in links:
        D.need(list(D.state(Path(name).lstat())) == expected and os.readlink(name) == target,
               "Native OS link changed while reading")
    D.need(D.state(resolved.lstat()) == D.state(st) and path.resolve(strict=True) == resolved,
           "Native OS input binding changed")
    return {**row, "path": str(resolved), "selectedPath": str(path), "identity": list(D.state(st)),
            "links": links, "ancestry": ancestry}


def shell_host_diagnostic(message, selected, component, item):
    """Only already-observed public OS metadata, within failure_reason's bound."""
    detail = json.dumps({"selectedPath": str(selected), "component": str(component),
                         "mode": format(item.st_mode, "06o"), "uid": item.st_uid, "gid": item.st_gid},
                        ensure_ascii=True, separators=(",", ":"))
    result = message + ": " + detail
    return result if len(result) <= 512 else message


def shell_host_binding(path, *, directory_only=False, absent=False, limit=MAX_BINARY):
    """Shell-only directory/absence companion to the unchanged OS file reader."""
    path = Path(path)
    if not directory_only and not absent:
        return protected_host_file(path, limit)
    D.need(path.is_absolute() and ".." not in path.parts, "Absolute shell host path required")
    resolved, pending, links, ancestry = Path("/"), list(path.parts[1:]), [], {}

    def directory(name, item):
        D.need(stat.S_ISDIR(item.st_mode) and item.st_uid == item.st_gid == 0 and not item.st_mode & 0o7022,
               shell_host_diagnostic("Unprotected shell directory ancestry", path, name, item))
        ancestry[str(name)] = [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid]

    directory(resolved, resolved.lstat())
    steps, missing = 0, None
    while pending:
        steps += 1
        D.need(steps <= 256, "Shell directory link/ancestry bound")
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        try:
            item = candidate.lstat()
        except FileNotFoundError:
            D.need(absent, "Required shell host path is absent")
            missing, resolved = str(candidate), candidate.joinpath(*pending)
            break
        D.need(item.st_uid == item.st_gid == 0,
               shell_host_diagnostic("Shell host path has a nonroot owner", path, candidate, item))
        if stat.S_ISLNK(item.st_mode):
            target = os.readlink(candidate)
            D.need(item.st_nlink == 1 and len(links) < 40 and 0 < len(target) <= 4096
                   and re.fullmatch(r"[A-Za-z0-9_./+\-]+", target) is not None
                   and D.state(candidate.lstat()) == D.state(item), "Shell host link differs")
            links.append([str(candidate), list(D.state(item)), target])
            target = Path(target)
            if target.is_absolute():
                resolved, parts = Path("/"), target.parts[1:]
            else:
                parts = target.parts
            pending = [*parts, *pending]
        else:
            D.need(not item.st_mode & 0o7022,
                   shell_host_diagnostic("Writable/special shell host input", path, candidate, item))
            resolved = candidate
            if pending or directory_only:
                directory(resolved, item)
            else:
                D.need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, "Nonordinary shell host file")
    row = {"path": str(resolved), "selectedPath": str(path), "links": links, "ancestry": ancestry}
    if missing is not None:
        row.update(absent=True, absentAt=missing)
    elif directory_only:
        row["directory"] = ancestry[str(resolved)]
    else:
        return protected_host_file(path, limit)
    for name, expected in ancestry.items():
        item = Path(name).lstat()
        D.need([item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid] == expected,
               "Shell host directory changed while reading")
    for name, expected, target in links:
        D.need(list(D.state(Path(name).lstat())) == expected and os.readlink(name) == target,
               "Shell host link changed while reading")
    if missing is None:
        D.need(path.resolve(strict=True) == resolved, "Shell host resolved directory changed")
    else:
        D.need(not Path(missing).exists() and not Path(missing).is_symlink(), "Shell host absence changed")
    return row


def shell_file_projection(row):
    """Portable original bytes/path/mode, not a claim to another VM's inode."""
    return {key: row[key] for key in ("path", "selectedPath", "size", "sha256")} | {"mode": stat.S_IMODE(row["identity"][2])}


def ubuntu_package_notice(admitted, rows, notices, actual, owned_files):
    """Bind notice DATA to the actual package, without trusting live /usr/share."""
    name = actual["binaryPackage"].split(":")[0]
    expected = admitted["ubuntu"]["packages"].get(name)
    D.need(expected is not None, "No reviewed Ubuntu notice mapping for " + name)
    keys = ("version", "architecture", "sourcePackage", "sourceVersion")
    D.need(all(actual[key] == expected[key] for key in keys),
           "Ubuntu notice package tuple differs for " + name + ": " + actual["version"])
    D.need(all("/" + entry["path"] in owned_files for entry in expected["ownedDocumentation"]),
           "Ubuntu package documentation roster differs for " + name)
    copyright = expected["copyright"]
    path = notices / copyright["noticePath"]
    body = D.read(path, 2 << 20)
    pin = rows[copyright["noticePath"]]
    D.need(len(body) == pin["size"] and hashlib.sha256(body).hexdigest() == pin["sha256"],
           "Ubuntu original copyright bytes differ for " + name)
    references = sorted({found.decode("ascii").rstrip(".") for found in re.findall(COMMON_LICENSE_PATTERN, body)})
    D.need(references == copyright["commonReferences"] and all(item in COMMON_LICENSES for item in references),
           "Ubuntu copyright common-license references differ for " + name)
    common = admitted["ubuntu"]["commonLicenses"]
    selected = {}
    for item in references:
        D.need(item in common, "Missing reviewed Ubuntu common license " + item)
        row = common[item]
        D.bound(notices / row["noticePath"], rows[row["noticePath"]])
        selected[item] = row
    return {"source": "reviewed-ubuntu-package-member-data", "packageArchive": expected["archive"],
            "copyright": copyright, "documentationPackages": expected["documentationPackages"],
            "commonLicenseSource": admitted["ubuntu"]["commonLicenseSource"], "commonLicenses": selected}


def linux_local_cargo_sources(packages, nodes, root, source):
    """The shared four-local/eight-declaration Linux source contract."""
    # The Linux-filtered graph includes the two maintained SDK sources, not
    # additional native platforms or arbitrary path/registry replacements.
    local_paths = {
        "mobile-release-kit-desktop": ("0.1.0", source / "desktop/src-tauri/Cargo.toml"),
        "mrk-linux-mount-observation": ("0.1.0", source / "desktop/native/linux-mount-observation/Cargo.toml"),
        "secret-service": ("5.2.0", source / "desktop/vendor/secret-service-5.2.0/Cargo.toml"),
        "zbus": ("5.19.0", source / "desktop/vendor/zbus-5.19.0/Cargo.toml"),
    }
    local = [row for row in packages if row.get("source") is None]
    D.need(len(local) == len(local_paths) and {row["name"] for row in local} == set(local_paths)
           and all((row["version"], row["manifest_path"]) == (local_paths[row["name"]][0], str(local_paths[row["name"]][1]))
                   for row in local),
           "Linux Cargo local source roster differs")
    D.need(all(row["id"] in nodes for row in local), "Linux Cargo active local graph differs")
    # Other-target helpers remain root dependency declarations, not packages.
    declarations = root.get("dependencies")
    D.need(type(declarations) is list
           and all(type(row) is dict and type(row.get("name")) is str for row in declarations),
           "Linux Cargo root dependency declarations differ")
    expected_declarations = [
        {"name": name, "path": str(source / ("desktop/native/" + directory)), "target": cfg,
         "source": None, "req": "*", "kind": None, "rename": None, "optional": False,
         "uses_default_features": True, "features": [], "registry": None}
        for name, directory, cfg in (
            ("mrk-linux-mount-observation", "linux-mount-observation",
             'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))'),
            ("mrk-macos-installed-native", "macos-installed-native",
             'cfg(all(target_os = "macos", target_arch = "aarch64"))'),
            ("mrk-windows-installed-native", "windows-installed-native",
             'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))'),
        )
    ]
    # Cargo retains the other-target dev declaration even in the filtered
    # Linux graph. It is not an active Windows package or compiler unit.
    expected_declarations.append({
        "name": "mrk-windows-installed-native", "path": str(source / "desktop/native/windows-installed-native"),
        "target": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
        "source": None, "req": "*", "kind": "dev", "rename": None, "optional": False,
        "uses_default_features": True, "features": ["qualification-result"], "registry": None,
    })
    for kind, support in ((None, []), ("dev", ["mrk-retrieval-test-support"])):
        expected_declarations.append({
            "name": "secret-service", "path": str(source / "desktop/vendor/secret-service-5.2.0"),
            "target": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
            "source": None, "req": "=5.2.0", "kind": kind, "rename": None, "optional": False,
            "uses_default_features": False, "features": ["rt-tokio-crypto-rust", *support], "registry": None,
        })
    # Cargo retains registry declarations for the patched SDK. Both roles must
    # resolve to the one exact local zbus above; a registry fallback is refused.
    for kind, support in ((None, []), ("dev", ["mrk-owned-test-support"])):
        expected_declarations.append({
            "name": "zbus", "target": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
            "source": "registry+https://github.com/rust-lang/crates.io-index", "req": "=5.19.0", "kind": kind,
            "rename": None, "optional": False, "uses_default_features": False,
            "features": ["tokio", *support], "registry": None,
        })
    local_names = {row["name"] for row in expected_declarations}
    local_declarations = [row for row in declarations
                          if row.get("source") is None or "path" in row or row["name"] in local_names]
    D.need(len(local_declarations) == len(expected_declarations)
           and sorted(D.canonical(row) for row in local_declarations)
           == sorted(D.canonical(row) for row in expected_declarations),
           "Linux Cargo local dependency declarations differ")
    return local_paths


def native_cargo_metadata(raw, source, target, notice_crates, locked, *, candidate=False):
    """Bind one fixed Linux profile to its exact original-notice input set.

    Package accounting is conservative: an admitted registry input need not
    have an active resolve node. This is not compiled/linked-unit attribution.
    """
    D.need(type(candidate) is bool and type(notice_crates) is list and notice_crates
           and all(type(row) is dict and all(type(row.get(key)) is str and row[key]
                   for key in ("name", "version", "license", "archiveSha256"))
                   and re.fullmatch(r"[0-9a-f]{64}", row["archiveSha256"]) is not None
                   for row in notice_crates), "Native notice crate roster is invalid")
    expected = {(row["name"], row["version"]): row for row in notice_crates}
    D.need(len(expected) == len(notice_crates), "Duplicate native notice crate")
    metadata = C.bounded_json(raw, LOG_LIMIT)
    packages, resolve = metadata.get("packages"), metadata.get("resolve")
    D.need(type(packages) is list and len(packages) == len(expected) + 4
           and type(resolve) is dict and type(metadata.get("version")) is int and metadata["version"] == 1
           and metadata.get("workspace_root") == str(source / "desktop/src-tauri")
           and metadata.get("target_directory") == str(target)
           and metadata.get("build_directory") == str(target), "Native Cargo roster/root/target differs")
    D.need(all(type(row) is dict and all(type(row.get(key)) is str and row[key]
                   for key in ("id", "name", "version", "manifest_path"))
                   and "source" in row and (row["source"] is None or type(row["source"]) is str)
                   for row in packages), "Native Cargo package identity is invalid")
    node_rows = resolve.get("nodes")
    D.need(type(node_rows) is list and all(type(row) is dict and type(row.get("id")) is str
           and row["id"] for row in node_rows), "Native Cargo resolve nodes are invalid")
    by_id = {row["id"]: row for row in packages}
    nodes = {row["id"]: row for row in node_rows}
    D.need(len(by_id) == len(packages) and len(nodes) == len(node_rows) and set(nodes) <= set(by_id),
           "Native Cargo metadata IDs differ/duplicate")
    roots = [row for row in packages if row["manifest_path"] == str(source / "desktop/src-tauri/Cargo.toml")]
    D.need(len(roots) == 1 and roots[0]["name"] == "mobile-release-kit-desktop" and roots[0]["version"] == "0.1.0"
           and resolve.get("root") == roots[0]["id"] and roots[0]["id"] in nodes
           and metadata.get("workspace_members") == [roots[0]["id"]]
           and metadata.get("workspace_default_members") == [roots[0]["id"]]
           and nodes[roots[0]["id"]].get("features") == ([] if candidate else FEATURES),
           "Native Cargo root/workspace/profile differs")
    for row in nodes.values():
        features, deps, dependencies = row.get("features"), row.get("deps"), row.get("dependencies")
        D.need(type(features) is list and all(type(name) is str for name in features)
               and len(features) == len(set(features)) and type(deps) is list
               and all(type(dep) is dict and type(dep.get("name")) is str and dep["name"]
                       and type(dep.get("pkg")) is str and dep["pkg"] in nodes for dep in deps)
               and len(deps) == len({(dep["name"], dep["pkg"]) for dep in deps})
               and type(dependencies) is list and all(type(item) is str for item in dependencies)
               and len(dependencies) == len(set(dependencies))
               and set(dependencies) == {dep["pkg"] for dep in deps}, "Native resolved Cargo edge/features differ")
        for dep in deps:
            kinds = dep.get("dep_kinds")
            D.need(type(kinds) is list and kinds and all(type(kind) is dict
                   and set(kind) == {"kind", "target"} and kind["kind"] in (None, "dev", "build")
                   and (kind["target"] is None or type(kind["target"]) is str) for kind in kinds)
                   and len(kinds) == len({D.canonical(kind) for kind in kinds}),
                   "Native resolved Cargo dependency roles differ")
    local_paths = linux_local_cargo_sources(packages, nodes, roots[0], source)
    local_ids = {row["id"] for row in packages if row["source"] is None}
    D.need(local_ids - {roots[0]["id"]} <= {dep["pkg"] for dep in nodes[roots[0]["id"]]["deps"]},
           "Native Cargo root lost an active local dependency")
    registry_rows = [row for row in packages if row["source"] is not None]
    registry = {(row["name"], row["version"]): row for row in registry_rows}
    D.need(len(registry) == len(registry_rows) and set(registry) == set(expected)
           and all(row["name"] not in local_paths for row in registry_rows),
           "Native Cargo source versions differ from original notices")
    registry_source = "registry+https://github.com/rust-lang/crates.io-index"
    D.need(type(locked) is dict and type(locked.get("package")) is list, "Native Cargo lock is invalid")
    lock_rows = [row for row in locked["package"] if "source" in row]
    lock = {(row["name"], row["version"]): row for row in lock_rows}
    D.need(len(lock) == len(lock_rows), "Duplicate native Cargo lock source")
    for key, row in expected.items():
        D.need(key in lock and registry[key]["source"] == registry_source
               and registry[key].get("license") == row["license"] and lock[key]["source"] == registry_source
               and lock[key].get("checksum") == row["archiveSha256"],
               "Cargo original notice/checksum correspondence differs")
    for row in packages:
        origin = registry_source if row["source"] is not None else "path+" + Path(row["manifest_path"]).parent.as_uri()
        D.need(row["id"] == origin + "#" + row["name"] + "@" + row["version"],
               "Native Cargo ID does not identify its exact source")
    return metadata, by_id, nodes


def native_source_notice_inputs(source, admitted, rows):
    """Bind reviewed archive-member references and maintained local originals."""
    for crate in admitted["crates"]:
        for member in crate.get("noticeMembers", []):
            prefix = crate["name"] + "-" + crate["version"] + "/"
            path = member["noticePath"]
            D.need(member["member"].startswith(prefix) and path == "notices/crates/" + member["member"]
                   and rows.get(path) == {"path": path, "size": member["size"], "sha256": member["sha256"]},
                   "Native original archive notice member differs")
    originals = admitted["localSourceNotices"]
    D.need(type(originals) is list and originals and all(type(row) is dict
           and set(row) == {"sourcePath", "noticePath"} for row in originals),
           "Native local source notice roster differs")
    D.need(len({row["sourcePath"] for row in originals}) == len(originals)
           and len({row["noticePath"] for row in originals}) == len(originals),
           "Duplicate native local source notice")
    inputs = []
    for row in originals:
        path = source / D.relative(row["sourcePath"])
        notice = D.relative(row["noticePath"])
        D.need(notice in rows, "Native local original notice is missing")
        D.bound(path, rows[notice])
        inputs.append({**D.file_record(path, 2 << 20), "path": str(path)})
    return inputs


def native_inputs(check, source, work, environment, cargo, rustc, metadata_raw, *, candidate=False):
    """Standard toolchain/support input provenance, not a linked-object census."""
    notice_source = source / "desktop/packaging/debian/native-notices"
    raw = D.read(notice_source / "inputs.json", 1 << 20)
    D.need(hashlib.sha256(raw).hexdigest() == NOTICE_INPUTS_SHA256, "Native source notice roster differs")
    admitted = D.decode(raw, 1 << 20)
    rows = D.records(admitted["files"])
    C.conventional_files(D, notice_source, sorted([*rows.values(), D.file_record(notice_source / "inputs.json")], key=lambda x: x["path"]))
    notices = work / "native-notices"
    notices.mkdir(mode=0o700)
    for name, row in rows.items():
        destination = notices / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        D.copy(notice_source / name, destination, row, 0o644)
    D.copy(notice_source / "inputs.json", notices / "inputs.json", D.file_record(notice_source / "inputs.json"), 0o644)
    locked = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.lock", 256 << 10).decode("utf-8"))
    # Cargo metadata has its own target root. The later compilation command's
    # private work/target output is a different path, not metadata authority.
    native_cargo_metadata(metadata_raw, source, source / "desktop/src-tauri/target",
                          admitted["crates"], locked, candidate=candidate)
    inputs = native_source_notice_inputs(source, admitted, rows)
    for row in admitted["crates"]:
        key = (row["name"], row["version"])
        candidates = list((work / "cargo/registry/cache").glob("*/" + key[0] + "-" + key[1] + ".crate"))
        D.need(len(candidates) == 1, "Native locked crate cache is ambiguous")
        record = D.file_record(candidates[0], 8 << 20)
        D.need(record["sha256"] == row["archiveSha256"], "Actual acquired crate differs from native notices")
        inputs.append({**record, "path": str(candidates[0])})
    toolchain = Path(rustc).parent.parent
    D.need(Path(cargo).parent.parent == toolchain and toolchain.is_relative_to(work / "rustup/toolchains"),
           "Compiler component root differs")
    manifest_path = toolchain / "lib/rustlib/multirust-channel-manifest.toml"
    channel = tomllib.loads(D.read(manifest_path, 2 << 20).decode("utf-8"))
    for pkg, target, key in (("rustc", TARGET, "rustcArchiveSha256"), ("rust-std", TARGET, "stdArchiveSha256"),
                             ("rust-src", "*", "sourceArchiveSha256")):
        D.need(channel["pkg"][pkg]["version"] == "1.98.0 (88d9e12ae 2026-08-18)"
               and channel["pkg"][pkg]["target"][target]["xz_hash"] == admitted["rust"][key],
               "Actual Rust component differs from reviewed original notices")
    for name, row in rows.items():
        prefix = "notices/rust-1.98.0/"
        if name.startswith(prefix) and not name.startswith(prefix + "source-package/"):
            path = toolchain / "share/doc/rust" / name.removeprefix(prefix)
            D.bound(path, row)
            inputs.append({**D.file_record(path, 2 << 20), "path": str(path)})
    # Use the actual standard component manifests, not only the rustc shim or
    # version text. This conservatively binds the compiler backend, bundled
    # GNU-linker entry/rust-lld, and the complete native std support set. No
    # linker wrapper or purported exact linked-object census is introduced.
    component_rosters, component_manifests = {}, []
    for component in ("rustc", "rust-std", "cargo"):
        path = toolchain / "lib/rustlib" / ("manifest-" + component + "-" + TARGET)
        lines = D.read(path, 128 << 10).decode("ascii").splitlines()
        D.need(0 < len(lines) <= 512 and all(line.startswith("file:") for line in lines),
               "Installed Rust component manifest differs")
        names = [D.relative(line.removeprefix("file:")) for line in lines]
        D.need(len(names) == len(set(names)), "Duplicate installed Rust component member")
        component_rosters[component] = set(names)
        component_manifests.append(path)
    support_prefix = "lib/rustlib/" + TARGET + "/lib/"
    std_names = component_rosters["rust-std"]
    D.need(all(name.startswith(support_prefix) and Path(name).suffix in (".rlib", ".rmeta", ".a", ".o", ".so") for name in std_names)
           and any(Path(name).name.startswith("libstd-") and name.endswith(".rlib") for name in std_names)
           and any(Path(name).name.startswith("libcompiler_builtins-") and name.endswith(".rlib") for name in std_names),
           "Rust standard/static support roster differs")
    D.need({str(path.relative_to(toolchain)) for path in (toolchain / support_prefix).iterdir() if not path.is_dir()} == std_names,
           "Actual installed Rust native support files differ from component manifest")
    compiler_names = {"bin/rustc", "lib/rustlib/" + TARGET + "/bin/rust-lld",
                      "lib/rustlib/" + TARGET + "/bin/gcc-ld/ld.lld"}
    compiler_names |= {name for name in component_rosters["rustc"]
                       if name.startswith("lib/libLLVM") or name.startswith("lib/librustc_driver-")}
    D.need(len(compiler_names) >= 5 and compiler_names <= component_rosters["rustc"]
           and "bin/cargo" in component_rosters["cargo"], "Actual standard Rust compiler/linker component missing")
    for path in [manifest_path, *component_manifests, *(toolchain / name for name in sorted(compiler_names | std_names | {"bin/cargo"}))]:
        inputs.append({**D.file_record(path, 512 << 20), "path": str(path)})
    D.need(sum(row["size"] for row in inputs) <= 1 << 30, "Native compiler/component input bound")
    os_files, os_packages, package_files = {}, {}, {}
    counter = 0

    def host(path, limit=MAX_BINARY):
        record = protected_host_file(path, limit)
        os_files[record["selectedPath"]] = record
        return record

    def package(name):
        nonlocal counter
        D.need(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name) is not None, "Native package name differs")
        if name in os_packages:
            return os_packages[name]
        D.need(len(os_packages) < 20, "Native OS package closure bound")
        counter += 1
        fields = "${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
        argv = ["/usr/bin/dpkg-query", "-W", "-f=" + fields, name]
        result = check.command("native-package-" + str(counter), argv, environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Native package query capture differs")
        values = result.stdout.decode("ascii").rstrip("\n").split("\t")
        D.need(len(values) == 6 and values[0].split(":")[0] == name.split(":")[0] and values[1] == "installed"
               and values[3] == "amd64" and all(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", values[i]) for i in (2, 5)),
               "Actual native package/version/architecture differs")
        listing = check.command("native-package-files-" + str(counter), ["/usr/bin/dpkg-query", "-L", name],
                                environment, work, timeout=15, limit=256 << 10)
        D.need(listing.stderr == b"", "Native package file query differs")
        files = listing.stdout.decode("utf-8").splitlines()
        D.need(0 < len(files) <= 8192 and all(p.startswith("/") and ".." not in Path(p).parts for p in files),
               "Native package file roster differs")
        row = {"binaryPackage": values[0], "version": values[2], "architecture": values[3],
               "sourcePackage": values[4], "sourceVersion": values[5], "queryArgv": argv,
               "querySha256": hashlib.sha256(result.stdout).hexdigest()}
        os_packages[name], package_files[name] = row, set(files)
        # The hosted image has a writable /usr/share. Copyright is inert DATA
        # from reviewed original package members, never authority from that
        # installed path. Bind each actual package in the original alias chain.
        row["copyright"] = ubuntu_package_notice(admitted, rows, notices, row, package_files[name])
        for documentation_package in row["copyright"]["documentationPackages"]:
            package(documentation_package)
        return row

    def owner_of(path):
        nonlocal counter
        counter += 1
        result = check.command("native-file-owner-" + str(counter), ["/usr/bin/dpkg-query", "-S", str(path)],
                               environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Native file ownership query differs")
        line = result.stdout.decode("ascii").rstrip("\n")
        suffix = ": " + str(path)
        D.need(line.endswith(suffix), "Native file package ownership differs")
        name = line[:-len(suffix)]
        package(name)
        return name

    cc = shutil.which("cc", path=environment["PATH"])
    D.need(cc is not None and Path(cc).is_absolute(), "Standard GNU compiler driver missing")
    driver = host(Path(cc))
    owner_of(Path(driver["path"]))
    version = check.command("native-gcc-version", [cc, "-dumpfullversion"], environment, work, timeout=15, limit=4096)
    D.need(version.stderr == b"" and re.fullmatch(rb"[0-9]+(?:\.[0-9]+){1,2}\n", version.stdout), "GNU compiler version differs")
    for name in ("collect2", "ld"):
        output = check.command("native-gcc-program-" + name, [cc, "-print-prog-name=" + name],
                               environment, work, timeout=15, limit=4096)
        D.need(output.stderr == b"" and output.stdout.count(b"\n") == 1, "GNU compiler-program query differs")
        selected = output.stdout.decode("ascii").rstrip("\n")
        selected = selected if selected.startswith("/") else shutil.which(selected, path=environment["PATH"])
        D.need(selected is not None and Path(selected).is_absolute(), "GNU standard linker program missing")
        program = host(Path(os.path.abspath(selected)))
        owner_of(Path(program["path"]))
    for index, name in enumerate(("Scrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o",
                                  "libgcc.a", "libgcc_eh.a", "libgcc_s.so", "libc.so", "libc_nonshared.a",
                                  "libutil.a", "librt.a", "libpthread.a", "libm.so", "libdl.a")):
        output = check.command("native-gcc-support-" + str(index), [cc, "-print-file-name=" + name],
                               environment, work, timeout=15, limit=4096)
        D.need(output.stderr == b"" and output.stdout.count(b"\n") == 1, "GNU support-file query differs")
        selected = Path(os.path.abspath(output.stdout.decode("ascii").rstrip("\n")))
        D.need(output.stdout.startswith(b"/"), "GNU compiler support file was not resolved")
        support_row = host(selected)
        owner_of(Path(support_row["path"]))
    # Prebind the finite GNU std support candidates before compilation; actual
    # new-output DT_NEEDED closure is evaluated separately below, never guessed.
    libraries = {}
    for soname, pkg in SONAME_PACKAGES.items():
        package(pkg)
        selected = Path("/usr/lib/x86_64-linux-gnu") / soname
        record = host(selected)
        aliases = {record["path"], record["selectedPath"], record["path"].replace("/usr/lib/", "/lib/", 1)}
        D.need(bool(aliases & package_files[pkg]), "Native shared object is not in its actual installed package")
        elf = elf_dependencies(D.read(Path(record["path"]), MAX_BINARY))
        D.need(elf["soname"] == soname, "Actual native shared-object SONAME differs")
        libraries[soname] = {"file": record, "package": pkg, "elf": elf}
    loader = host(Path("/lib64/ld-linux-x86-64.so.2"))
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"], "Actual interpreter binding differs")
    return {"notices": notices, "inputs": inputs, "osFiles": os_files, "osPackages": os_packages,
            "libraries": libraries, "rust": {**admitted["rust"], "cargoVersion": channel["pkg"]["cargo"]["version"],
                "cargoArchiveSha256": D.sha(channel["pkg"]["cargo"]["target"][TARGET]["xz_hash"])},
            "gccVersion": version.stdout.decode("ascii").strip()}


def finish_native_inputs(check, work, environment, native, outputs, *, candidate=False):
    D.need(set(outputs) == ({"candidate"} if candidate else {"P0", "F1", "fixture", "libtest"}),
           "Fixed compiler output closure roster differs")
    closures = {}
    for label, path in outputs.items():
        raw = D.read(path, MAX_BINARY)
        observed = elf_dependencies(raw)
        D.need(observed["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and observed["soname"] is None
               and observed["needed"], "Compiler output is not the expected native executable")
        # The interpreter is a dependency even if a linker omits a redundant
        # direct DT_NEEDED entry for it.
        pending, visited = [observed, native["libraries"]["ld-linux-x86-64.so.2"]["elf"]], {"ld-linux-x86-64.so.2"}
        while pending:
            current = pending.pop()
            for soname in current["needed"]:
                selected = native["libraries"][soname]
                D.need(set(current["versionNeeds"].get(soname, [])) <= set(selected["elf"]["versionDefinitions"]),
                       "Actual native shared object lacks required symbol versions")
                if soname not in visited:
                    visited.add(soname)
                    pending.append(selected["elf"])
        closures[label] = {"file": {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                           "elf": observed, "objects": sorted(visited),
                           "packages": sorted({native["libraries"][name]["package"] for name in visited})}
    for row in native["inputs"]:
        D.bound(Path(row["path"]), row)
    for selected, row in native["osFiles"].items():
        D.need(D.same(protected_host_file(Path(selected)), row), "Native compiler/support input changed during compilation")
    for index, row in enumerate(native["osPackages"].values()):
        result = check.command("native-package-recheck-" + str(index), row["queryArgv"], environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and hashlib.sha256(result.stdout).hexdigest() == row["querySha256"],
               "Native OS package changed during compilation")
    required = sorted({pkg for label in (("candidate",) if candidate else ("P0", "F1", "fixture"))
                       for pkg in closures[label]["packages"]})
    depends = ", ".join(pkg.split(":")[0] + " (= " + native["osPackages"][pkg]["version"] + ")" for pkg in required)
    record = {"rust": native["rust"], "gccVersion": native["gccVersion"], "compilerInputs": native["inputs"],
              "osFiles": list(native["osFiles"].values()), "osPackages": native["osPackages"],
              "sharedObjects": native["libraries"], "outputs": closures,
              "depends": depends, "scope": "Bound standard compiler/components/GCC/CRT/static-support and actual ELF/package/version/notice closure; not an exact linked-object census or product qualification."}
    D.write(native["notices"] / "BUILD-INPUTS.json", D.canonical(record), 0o644)
    P = local("prepare_runtime")
    notices = [{**D.file_record(path, 2 << 20), "path": path.relative_to(native["notices"]).as_posix()}
               for path in P.files(native["notices"])]
    notices.sort(key=lambda row: row["path"])
    D.need(sum(row["size"] for row in notices) <= 64 << 20, "Complete native notice input bound")
    return record, notices, depends


def installed_graph(runtime, rows, native):
    """Only A's three native objects and this fresh feature-off libtest."""
    objects = {}
    for name in RUNTIME_ELF:
        row = rows[name]
        D.bound(runtime / name, row)
        raw = D.read(runtime / name, 64 << 20)
        objects[name] = {"file": row, "elf": elf_dependencies(raw, runtime_path=name)}
    libraries = {**native["sharedObjects"], **{row["elf"]["soname"]: row for name, row in objects.items()
                                              if name != "python/bin/python3"}}

    def closure(first):
        visited, pending = {"ld-linux-x86-64.so.2"}, [first, libraries["ld-linux-x86-64.so.2"]["elf"]]
        while pending:
            current = pending.pop()
            for soname in current["needed"]:
                D.need(soname in libraries, "Unbound installed ELF dependency")
                selected = libraries[soname]["elf"]
                D.need(set(current["versionNeeds"].get(soname, [])) <= set(selected["versionDefinitions"]),
                       "Installed dependency lacks an original required symbol version")
                if soname not in visited:
                    visited.add(soname)
                    pending.append(selected)
        return visited

    private = {"libssl.so.3", "libcrypto.so.3"}
    runtime_names = closure(objects["python/bin/python3"]["elf"])
    D.need(runtime_names == private | {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"},
           "The fixed A native graph differs from the reviewed original")
    candidate = native["outputs"]["candidate"]
    candidate_names = closure(candidate["elf"])
    D.need(candidate_names == set(candidate["objects"]) and not candidate_names & private,
           "Candidate native closure differs")
    os_names = sorted((runtime_names | candidate_names) - private)
    startup = {prefix + name for prefix in ("", "python/", "python/bin/")
               for name in ("pyvenv.cfg", "python3._pth", "pybuilddir.txt")}
    D.need(not startup & set(rows) and not any(name.startswith("python/lib/glibc-hwcaps/") for name in rows)
           and all("python/lib/" + name not in rows for name in os_names)
           and {name for name in rows if re.search(r"\.so(?:\.[0-9]+)*$", name)}
               == {"python/lib/libssl.so.3", "python/lib/libcrypto.so.3"},
           "A inventory contains a startup/native search alternative")
    return {"manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
            "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"], "runtime": objects,
            "candidate": candidate, "runtimeObjects": sorted(runtime_names), "osNames": os_names,
            "libraries": {name: native["sharedObjects"][name] for name in os_names},
            "privateRunpaths": {name: row[1] for name, row in RUNTIME_ELF.items()},
            "scope": "Fixed A and original candidate ELF DATA; not loader selection or execution authority"}


def static_ldconfig(raw):
    """The one libc-bin ldconfig.real must have no interpreter/needed edge."""
    D.need(type(raw) is bytes and 64 <= len(raw) <= 4 << 20, "Static ldconfig ELF bound")
    ident, kind, machine, version, _, offset, _, _, size, phsize, count, _, _, _ = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    D.need(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in (2, 3) and machine == 62 and version == 1
           and size == 64 and phsize == 56 and 0 < count <= 32 and offset + count * phsize <= len(raw),
           "Fixed ldconfig is not bounded native ELF")
    for index in range(count):
        segment = struct.unpack_from("<IIQQQQQQ", raw, offset + index * phsize)
        D.need(segment[0] != 3 and segment[2] <= len(raw) and segment[5] <= len(raw) - segment[2],
               "ldconfig has an interpreter or invalid segment")
        if segment[0] == 2:
            D.need(0 < segment[5] <= 65536 and segment[5] % 16 == 0, "Static ldconfig dynamic bound")
            ended = False
            for at in range(segment[2], segment[2] + segment[5], 16):
                tag, _ = struct.unpack_from("<qQ", raw, at)
                if tag == 0:
                    ended = True
                    break
                D.need(tag not in {1, 15, 29, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF},
                       "ldconfig has a dynamic dependency/search/audit/filter edge")
            D.need(ended, "Static ldconfig dynamic table is unterminated")


def installed_candidate(work, sha):
    artifact = work / "admitted-candidate"
    raw = D.read(artifact / "candidate-roster.json", 128 << 10)
    digest = D.sha(os.environ.get("MRK_INSTALLED_CANDIDATE_ROSTER_SHA256"))
    D.need(hashlib.sha256(raw).hexdigest() == digest, "Original same-job candidate roster differs")
    roster = D.decode(raw, 128 << 10)
    producer_attempt = os.environ.get("MRK_INSTALLED_CANDIDATE_PRODUCER_ATTEMPT", "")
    artifact_id = os.environ.get("MRK_INSTALLED_CANDIDATE_ARTIFACT_ID", "")
    D.need(re.fullmatch(r"[1-9][0-9]{0,19}", producer_attempt) is not None
           and re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id) is not None
           and int(producer_attempt) <= int(os.environ["GITHUB_RUN_ATTEMPT"]),
           "Original candidate producer attempt is missing or newer than this consumer")
    D.need(type(roster) is dict and set(roster) == {"sourceSha", "runId", "attempt", "files"}
           and (roster["sourceSha"], roster["runId"], roster["attempt"])
               == (sha, os.environ["GITHUB_RUN_ID"], producer_attempt),
           "Candidate is not from this exact source/run/original producer attempt")
    rows = D.records(roster["files"])
    D.need(len(rows) <= 512 and sum(row["size"] for row in rows.values()) <= 1 << 30
           and {"candidate", "compiler.json", "candidate-native.json", "candidate-compile.stdout", "source.json", "result.json"} <= set(rows),
           "Original candidate artifact roster is incomplete/oversized")
    C.conventional_files(D, artifact, sorted([*rows.values(), {"path": "candidate-roster.json", "size": len(raw), "sha256": digest}],
                                           key=lambda row: row["path"]))
    compiler = D.decode(D.read(artifact / "compiler.json", 1 << 20))
    result = D.decode(D.read(artifact / "result.json", 1 << 20))
    D.need(compiler["sourceSha"] == result["sourceSha"] == sha and compiler["features"] == result["features"] == []
           and (result["runId"], result["attempt"]) == (roster["runId"], producer_attempt)
           and (compiler["runId"], compiler["attempt"]) == (roster["runId"], producer_attempt)
           and compiler["manifestSha256"] == C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"]
           and compiler["protocolSha256"] == C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"]
           and result["compilations"] == ["candidate"] and result["candidateExecuted"] is False
           and result["supplierRebuilt"] is result["helper11Rerun"] is result["qualified"] is False,
           "Original candidate compiler/profile/compile-only result differs")
    original, exported = compiler["originalArtifacts"]["candidate"], compiler["exportedArtifacts"]["candidate"]
    path = compiled_artifact(D.read(artifact / "candidate-compile.stdout", LOG_LIMIT), Path(compiler["source"]),
                             Path(compiler["target"]), library=True, candidate=True)
    commands = [row for row in result["commands"] if row["phase"] == "candidate-compile"]
    D.need(len(commands) == 1 and type(commands[0]["exitCode"]) is int and commands[0]["exitCode"] == 0
           and commands[0]["argv"] == compile_argv(commands[0]["argv"][0], Path(compiler["source"]), Path(compiler["target"]),
                                                  library=True, candidate=True)
           and str(path) == original["path"] and original["identity"][:2] != exported["identity"][:2]
           and all(original[key] == exported[key] == rows["candidate"][key] for key in ("size", "sha256")),
           "Original fresh candidate/export/command correspondence differs")
    graph = D.decode(D.read(artifact / "candidate-native.json", 1 << 20))
    D.need(graph["manifestSha256"] == compiler["manifestSha256"] and graph["protocolSha256"] == compiler["protocolSha256"]
           and graph["candidate"] == compiler["nativeInputs"]["outputs"]["candidate"]
           and elf_dependencies(D.read(artifact / "candidate", MAX_BINARY)) == graph["candidate"]["elf"],
           "Transported candidate/native graph differs")
    return {**rows["candidate"], "path": str(artifact / "candidate")}, compiler, graph, digest, producer_attempt, artifact_id


def installed_shell_candidate(work, sha):
    """Admit both exact original shell outputs, including failed-job-only reuse."""
    artifact = work / "admitted-shell"
    raw = D.read(artifact / "shell-roster.json", SHELL_ROSTER_LIMIT)
    digest = D.sha(os.environ.get("MRK_INSTALLED_SHELL_ROSTER_SHA256"))
    D.need(hashlib.sha256(raw).hexdigest() == digest, "Original shell artifact roster digest differs")
    roster = D.decode(raw, SHELL_ROSTER_LIMIT)
    producer_attempt = os.environ.get("MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT", "")
    artifact_id = os.environ.get("MRK_INSTALLED_SHELL_ARTIFACT_ID", "")
    D.need(re.fullmatch(r"[1-9][0-9]{0,19}", producer_attempt) is not None
           and re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id) is not None
           and int(producer_attempt) <= int(os.environ["GITHUB_RUN_ATTEMPT"]),
           "Original shell producer attempt/artifact identity differs")
    D.need(type(roster) is dict and set(roster) == {"sourceSha", "sourceTree", "runId", "attempt", "files"}
           and (roster["sourceSha"], roster["runId"], roster["attempt"])
               == (sha, os.environ["GITHUB_RUN_ID"], producer_attempt)
           and re.fullmatch(r"[0-9a-f]{40}", roster["sourceTree"]) is not None,
           "Shell candidate is not the exact source/tree/run/original producer")
    rows = D.records(roster["files"])
    required = {"compiler.json", "source.json", "result.json", "shell-native.json", "frontend.json",
                "shell-host-bindings.json", "shell-compile.stdout", "shell-compile.stderr", "shell-locked-inputs.stdout", *SHELL_EXPORTS.values()}
    D.need(required <= set(rows) and len(rows) <= 1536 and sum(row["size"] for row in rows.values()) <= 1536 << 20,
           "Original complete shell artifact roster is missing/oversized")
    C.conventional_files(D, artifact, sorted([*rows.values(), {"path": "shell-roster.json", "size": len(raw), "sha256": digest}],
                                           key=lambda row: row["path"]))
    compiler = D.decode(D.read(artifact / "compiler.json", SHELL_METADATA_LIMIT), SHELL_METADATA_LIMIT)
    source_record = D.decode(D.read(artifact / "source.json", 1 << 20), 1 << 20)
    result = D.decode(D.read(artifact / "result.json", 1 << 20), 1 << 20)
    identity = (sha, roster["sourceTree"], os.environ["GITHUB_RUN_ID"], producer_attempt)
    D.need(all(tuple(row[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")) == identity
               and row["features"] == SHELL_FEATURES for row in (compiler, source_record, result))
           and compiler["manifestSha256"] == C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"]
           and compiler["protocolSha256"] == C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"]
           and compiler["sourceInputs"] == source_record["sourceInputs"] == shell_source_manifest(SOURCE)
           and result["compilations"] == ["normal", "observer"]
           and type(result["cargoBuilds"]) is int and result["cargoBuilds"] == 1
           and type(result["frontendBuilds"]) is int and result["frontendBuilds"] == 1
           and all(result[key] is False for key in ("shellExecuted", "observerExecuted", "supplierRebuilt",
                                                    "packageBuilt", "helper11Rerun", "qualified"))
           and D.same(result.get("compilerCleanup"), SHELL_CLEANUP_SUCCESS),
           "Original shell source/anchors/features/compile-only result differs")
    source, target = Path(compiler["source"]), Path(compiler["target"])
    D.need(source.is_absolute() and target.is_absolute() and ".." not in (*source.parts, *target.parts),
           "Original shell compiler source/target path differs")
    selections, units = shell_compiled_artifacts(D.read(artifact / "shell-compile.stdout", SHELL_COMPILE_LIMIT), source, target)
    D.need(D.same(selections, compiler["selections"]) and D.same(units, compiler["compilerUnits"]),
           "Original shell Cargo unit/selected-output records differ")
    commands = [row for row in result["commands"] if row["phase"] == "shell-compile"]
    D.need(len(commands) == 1 and type(commands[0]["exitCode"]) is int and commands[0]["exitCode"] == 0
           and commands[0]["ordinaryOwnerReturned"] is True
           and commands[0]["argv"] == shell_compile_argv(compiler["cargo"], source, target),
           "Original single shell build command/result differs")
    metadata_raw = D.read(artifact / "shell-locked-inputs.stdout", SHELL_METADATA_LIMIT)
    _, packages, nodes = shell_cargo_metadata(metadata_raw, source, target)
    D.need(hashlib.sha256(metadata_raw).hexdigest() == compiler["compilerInputs"]["metadataSha256"]
           and all(row["package_id"] in packages for row in units), "Transported full shell metadata/compiler units differ")
    shell_compiler_units(units, packages, nodes)
    root_id = next(key for key, value in packages.items() if value["manifest_path"] == str(source / "desktop/src-tauri/Cargo.toml"))
    D.need(all(row["packageId"] == root_id for row in selections.values()), "Shell output package differs from Cargo root")
    native = D.decode(D.read(artifact / "shell-native.json", SHELL_METADATA_LIMIT), SHELL_METADATA_LIMIT)
    frontend = D.decode(D.read(artifact / "frontend.json", 1 << 20), 1 << 20)
    D.bound(artifact / "shell-native.json", compiler["nativeRecord"])
    D.bound(artifact / "frontend.json", compiler["frontendRecord"])
    D.need(D.same(native, compiler["nativeInputs"]) and frontend["sourceInputs"] == compiler["sourceInputs"]
           and frontend["embeddedBy"] == "tauri/custom-protocol" and frontend["devServer"] is False
           and frontend["node"] == C.NODE and not frontend["dist"]["links"]
           and "index.html" in D.records(frontend["dist"]["files"]),
           "Shell native/embedded frontend transport correspondence differs")
    D.need(native["manifestSha256"] == compiler["manifestSha256"] and native["protocolSha256"] == compiler["protocolSha256"]
           and set(native["runtime"]) == set(RUNTIME_ELF)
           and native["runtimeObjects"] == sorted({"libssl.so.3", "libcrypto.so.3", "libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"})
           and native["privateRunpaths"] == {name: value[1] for name, value in RUNTIME_ELF.items()},
           "Original A graph namespace/anchors differ from the shell transport")
    D.bound(artifact / "shell-host-bindings.json", native["hostBindingsRecord"])
    bindings = D.decode(D.read(artifact / "shell-host-bindings.json", SHELL_METADATA_LIMIT), SHELL_METADATA_LIMIT)
    D.need({path: shell_file_projection(row) for path, row in bindings["files"].items()} == native["osFiles"],
           "Complete original shell host bindings differ from the portable native graph")
    lifecycle = local("ubuntu_publication_lifecycle")
    data = native["runtimeData"]
    D.need(len(data["records"]) == len(lifecycle.SHELL_DATA_ROOTS)
           and set(data["suppliers"]["roots"]) == set(data["caches"]["roots"]) == {path for path, _ in lifecycle.SHELL_DATA_ROOTS},
           "Original complete fixed shell DATA roster differs")
    for index, ((root_name, kind), record) in enumerate(zip(lifecycle.SHELL_DATA_ROOTS, data["records"])):
        leaf = "shell-data-" + str(index) + ".json"
        D.need(record["path"] == leaf and leaf in rows and all(record[key] == rows[leaf][key] for key in ("size", "sha256")),
               "Original per-root shell DATA member is missing or relabelled")
        D.bound(artifact / leaf, record)
        detail = D.decode(D.read(artifact / leaf, 2 << 20), 2 << 20)
        entries = detail["entries"]
        D.need(type(entries) is list and len(entries) <= 32768
               and entries == sorted(entries, key=lambda row: row["path"])
               and len({row["path"] for row in entries}) == len(entries), "Original shell DATA member order/uniqueness differs")
        for label, generated in (("suppliers", False), ("caches", True)):
            selected = [row for row in entries if lifecycle.shell_generated_data(str(Path(root_name) / row["path"])) is generated]
            summary = {"kind": kind, "present": selected[0]["present"] if selected else None, "entryCount": len(selected),
                       "fileCount": sum(row["kind"] == "file" and row["present"] for row in selected),
                       "byteCount": sum(row.get("size", 0) for row in selected), "sha256": hashlib.sha256(D.canonical(selected)).hexdigest()}
            D.need(summary == data[label]["roots"][root_name], "Original shell DATA summary is not derived from its full detail")
    D.need(all(hashlib.sha256(D.canonical(data[label]["roots"])).hexdigest() == data[label]["sha256"]
               for label in ("suppliers", "caches")), "Original shell DATA summary digest differs")
    D.need(set(compiler["originalArtifacts"]) == set(compiler["exportedArtifacts"]) == set(native["outputs"]) == set(SHELL_EXPORTS),
           "Original shell output roles differ")
    binaries = {}
    for role, leaf in SHELL_EXPORTS.items():
        original, exported = compiler["originalArtifacts"][role], compiler["exportedArtifacts"][role]
        native_file = native["outputs"][role]["file"]
        D.need(original["path"] == selections[role]["path"] and Path(exported["path"]).name == leaf
               and original["identity"][:2] != exported["identity"][:2]
               and all(original[key] == exported[key] == rows[leaf][key] == native_file[key] for key in ("size", "sha256"))
               and elf_dependencies(D.read(artifact / leaf, MAX_BINARY), shell=True) == native["outputs"][role]["elf"],
               "Original fresh shell/native/export correspondence differs")
        binaries[role] = {**rows[leaf], "path": str(artifact / leaf)}
    return binaries, compiler, native, digest, producer_attempt, artifact_id


def installed_u_inputs(work):
    accepted = INSTALLED_U_INPUTS
    D.need(type(accepted) is dict and set(accepted) == {"sourceSha", "runId", "attempt", "artifactId", "files"},
           "Actual independently accepted U lifecycle evidence is not yet pinned")
    D.need(re.fullmatch(r"[0-9a-f]{40}", accepted["sourceSha"]) is not None
           and all(type(accepted[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", accepted[key]) is not None
                   for key in ("runId", "attempt", "artifactId")), "Accepted U identity is incomplete")
    artifact = work / "admitted-u"
    C.conventional_files(D, artifact, accepted["files"])
    compiler = D.decode(D.read(artifact / "compiler.json", 1 << 20))
    result = D.decode(D.read(artifact / "result.json", 1 << 20))
    # These already byte-pinned records use the lifecycle's decimal deadline,
    # not the conventional inventory's integer-only DATA format.
    lifecycle = local("ubuntu_publication_lifecycle")
    start = lifecycle.decode(D.read(artifact / "lifecycle-unit-start.json", 1 << 20), 1 << 20)
    stop = lifecycle.decode(D.read(artifact / "lifecycle-unit-stop.json", 1 << 20), 1 << 20)
    body = D.read(artifact / "lifecycle-unit-result.json", 1 << 20)
    commands = [row for row in result["commands"] if row["phase"] == "root-lifecycle"]
    D.need(len(commands) == 1 and compiler["sourceSha"] == result["sourceSha"] == start["sourceSha"] == accepted["sourceSha"]
           and start["unit"]["Id"] == "mrk-ubuntu-native-" + accepted["runId"] + "-" + accepted["attempt"] + ".service"
           and stop["result"] == {"path": "unit-result.json", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
           and result["lifecycle"]["state"] == "p0-f1-lifecycle-observed" and result["helper11Rerun"] is False
           and result["qualified"] is False, "Pinned U original source/lifecycle/finality differs")
    lifecycle.verify_finality(start, stop, commands[0]["exitCode"])
    packages = {}
    for label, manifest, version in (("P0", C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"], "0.0.0+mrk.lifecycle.0"),
                                     ("F1", F1_MANIFEST_SHA256, "0.0.0+mrk.lifecycle.1")):
        row = D.file_record(artifact / (label + ".deb"), MAX_DEB)
        D.need(all(row[key] == result["packages"][label][key] for key in ("size", "sha256"))
               and (result["packages"][label]["manifestSha256"], result["packages"][label]["version"]) == (manifest, version),
               "Accepted U package bytes/anchors differ")
        packages[label] = {**row, "path": str(artifact / (label + ".deb")), "manifestSha256": manifest, "version": version}
    library = D.file_record(artifact / "libtest", MAX_BINARY)
    D.need(all(library[key] == compiler["library"][key] for key in ("size", "sha256")), "Original U platform libtest differs")
    return {**library, "path": str(artifact / "libtest")}, packages, compiler, {key: accepted[key] for key in accepted if key != "files"}


def installed_os_inputs(check, work, graph, candidate_compiler, u_compiler):
    names = graph["osNames"]
    D.need(type(names) is list and names == sorted(set(names)) and set(names) <= set(SONAME_PACKAGES)
           and {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"} <= set(names), "Fixed full installed OS graph differs")
    # The prior platform libtest keeps its ORIGINAL U source/closure. Never
    # relabel it as a newly compiled candidate from this source.
    old_native = u_compiler["nativeInputs"]
    required = sorted(set(names) | set(old_native["outputs"]["libtest"]["objects"]))
    D.need(set(required) <= set(SONAME_PACKAGES), "U platform has an unreviewed OS dependency")
    libraries = {}
    for name in required:
        current = protected_host_file(Path("/usr/lib/x86_64-linux-gnu") / name)
        expected = candidate_compiler["nativeInputs"]["sharedObjects"][name]
        old = old_native["sharedObjects"][name]
        raw = D.read(Path(current["path"]), MAX_BINARY)
        D.need(all(current[key] == expected["file"][key] == old["file"][key] for key in ("size", "sha256"))
               and elf_dependencies(raw) == expected["elf"] == old["elf"],
               "Actual VM dependency differs from accepted U/new candidate compiler closure")
        libraries[name] = {"file": current, "elf": expected["elf"]}
    loader = protected_host_file(Path("/lib64/ld-linux-x86-64.so.2"))
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"], "Actual installed loader alias differs")
    tool = protected_host_file(Path("/usr/sbin/ldconfig.real"), 4 << 20)
    static_ldconfig(D.read(Path(tool["path"]), 4 << 20))
    fields = "${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    packages = {}
    for index, package in enumerate(sorted({SONAME_PACKAGES[name] for name in required} | {"libc-bin"})):
        result = check.command("installed-os-package-" + str(index), ["/usr/bin/dpkg-query", "-W", "-f=" + fields, package],
                               env, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Original VM package query differs")
        row = result.stdout.decode("ascii").rstrip("\n").split("\t")
        key = "libc6:amd64" if package == "libc-bin" else package
        expected = candidate_compiler["nativeInputs"]["osPackages"][key]
        old = old_native["osPackages"][key]
        D.need(len(row) == 6 and row[0].split(":")[0] == package.split(":")[0] and row[1] == "installed" and row[3] == "amd64"
               and (row[2], row[3], row[4], row[5])
                   == tuple(expected[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion"))
                   == tuple(old[key] for key in ("version", "architecture", "sourcePackage", "sourceVersion")),
               "Actual VM package/source/version differs from original U/candidate compilation")
        listing = check.command("installed-os-package-files-" + str(index), ["/usr/bin/dpkg-query", "-L", package],
                                env, work, timeout=15, limit=256 << 10)
        paths = listing.stdout.decode("ascii").splitlines()
        D.need(listing.stderr == b"" and 0 < len(paths) <= 8192
               and all(path.startswith("/") and ".." not in Path(path).parts for path in paths),
               "Actual VM package member roster differs")
        members = [tool] if package == "libc-bin" else [libraries[name]["file"] for name in required if SONAME_PACKAGES[name] == package]
        D.need(all({member["path"], member["selectedPath"], member["path"].replace("/usr/lib/", "/lib/", 1)} & set(paths)
                   for member in members), "Actual VM dependency package member missing")
        packages[package] = row
    cache = protected_host_file(Path("/etc/ld.so.cache"), 16 << 20)
    try:
        Path("/etc/ld.so.preload").lstat()
    except FileNotFoundError:
        pass
    else:
        raise D.Refused("Ambient loader preload is present")
    return {"libraries": libraries, "loader": loader, "ldconfig": tool, "cache": cache, "packages": packages,
            "osNames": required, "graph": graph, "externalPrerequisites":
                "Accepted OS/bootstrap and initial mounts; administrator prevents concurrent cache/dependency replacement. "
                "These DATA records and later maps do not create that trust."}


def installed_shell_os_inputs(check, work, native, compiler, u_compiler):
    """Bind this VM to the shell compiler; accepted U compares only shared inputs."""
    D.need(D.same(native, compiler["nativeInputs"]) and set(native["outputs"]) == set(SHELL_EXPORTS)
           and set(native["programs"]) == set(SHELL_PROGRAMS) and set(native["scripts"]) == set(SHELL_SCRIPTS)
           and 1 <= len(native["sharedObjects"]) <= SHELL_MAX_LIBRARIES and 1 <= len(native["osFiles"]) <= 512,
           "Original shell native profile/closure differs")
    old = u_compiler["nativeInputs"]
    D.need(set(old["outputs"]["libtest"]["objects"]) <= set(native["sharedObjects"]),
           "Accepted U platform closure is absent from the shell host policy")
    current_files, libraries, programs, modules, scripts = {}, {}, {}, {}, {}
    for selected, row in native["osFiles"].items():
        check.phase = "shell-native-input:" + selected
        current = protected_host_file(Path(selected))
        D.need(shell_file_projection(current) == row, "Actual VM native input differs from original shell compiler")
        current_files[selected] = current

    def executable(row, role):
        selected = row["file"]["selectedPath"]
        check.phase = "shell-native-" + role + ":" + selected
        current = current_files[selected]
        elf = shell_elf_record(D.read(Path(current["path"]), MAX_BINARY), role=role, selected=selected)
        D.need(elf == row["elf"] and shell_file_projection(current) == row["file"],
               "Actual VM fixed shell ELF input differs")
        for name in elf["needed"]:
            provider = native["sharedObjects"].get(name)
            D.need(provider is not None and provider["file"]["selectedPath"] == shell_provider_path(selected, elf.get("runpath"), name)
                   and set(elf["versionNeeds"].get(name, [])) <= set(provider["elf"]["versionDefinitions"]),
                   "Actual VM shell dependency edge/provider context differs")
        # Complete current ancestry/link proofs are held once in osFiles.
        return {"file": {**shell_file_projection(current), "identity": current["identity"]},
                "elf": elf, "package": row["package"]}

    for name, row in native["sharedObjects"].items():
        current = executable(row, "provider")
        D.need(current["elf"]["soname"] == name, "Actual VM shell provider SONAME differs")
        if name in old["sharedObjects"]:
            accepted = old["sharedObjects"][name]
            D.need(all(current["file"][key] == accepted["file"][key] for key in ("size", "sha256"))
                   and current["elf"] == accepted["elf"], "Common shell/U native provider differs from accepted U")
            current_package = native["osPackages"][row["package"]]
            old_package = old["osPackages"][accepted["package"]]
            D.need(all(current_package[key] == old_package[key]
                       for key in ("version", "architecture", "sourcePackage", "sourceVersion")),
                   "Common shell/U package source/version differs")
        libraries[name] = current
    for source_rows, destination, role in ((native["programs"], programs, "program"), (native["modules"], modules, "module")):
        for name, row in source_rows.items():
            destination[name] = executable(row, role)
    for name, row in native["scripts"].items():
        D.need(shell_file_projection(current_files[name]) == row["file"] and row["interpreter"] == "/bin/sh",
               "Actual VM wrapper/interpreter bytes differ")
        scripts[name] = {**row, "file": {**row["file"], "identity": current_files[name]["identity"]}}
    roots, root_bindings, module_paths = shell_module_inventory()
    D.need(D.same(roots, native["moduleRoots"]) and set(module_paths) == set(modules),
           "Actual VM finite module directory roster differs")
    private_search = shell_private_search([*native["sharedObjects"].values(), *native["programs"].values(),
                                           *native["modules"].values()], native["sharedObjects"])
    D.need(D.same(private_search, native["privateSearch"]), "Original shell private search graph differs")
    for row in private_search:
        current = shell_host_binding(Path(row["path"]), absent=True)
        D.need(shell_file_projection(current) == native["sharedObjects"][row["name"]]["file"] if row["selected"]
               else current.get("absent") is True, "Actual VM private shell search alternative differs")
    lifecycle = local("ubuntu_publication_lifecycle")
    snapshot = lifecycle.shell_data_snapshot(shell_host_binding)
    D.need(D.same(snapshot["suppliers"], native["runtimeData"]["suppliers"])
           and D.same(snapshot["eglLibraries"], native["runtimeData"]["eglLibraries"])
           and all(set(paths) <= set(modules) for paths in snapshot["moduleSelections"].values()),
           "Actual VM supplier DATA or generated module selection differs from the admitted profile")
    runtime_data = shell_data_records(snapshot, check.root / "public", "shell-consumer-data")
    fields = "${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    packages = {}
    D.need(0 < len(native["osPackages"]) <= 256, "Shell consumer package count bound")
    for index, (name, expected) in enumerate(sorted(native["osPackages"].items())):
        D.need(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name) is not None, "Shell consumer package name differs")
        result = check.command("installed-shell-package-" + str(index), ["/usr/bin/dpkg-query", "-W", "-f=" + fields, name],
                               environment, work, timeout=15, limit=64 << 10)
        row = result.stdout.decode("ascii").rstrip("\n").split("\t")
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and len(row) == 6 and row[1] == "installed"
               and [row[i] for i in (0, 2, 3, 4, 5)] == [expected[key] for key in
                    ("binaryPackage", "version", "architecture", "sourcePackage", "sourceVersion")],
               "Actual VM shell package/source/version differs from original compiler")
        listing = check.command("installed-shell-package-files-" + str(index), ["/usr/bin/dpkg-query", "-L", name],
                                environment, work, timeout=15, limit=1 << 20)
        D.need(listing.stderr == b"" and hashlib.sha256(listing.stdout).hexdigest() == expected["memberQuerySha256"],
               "Actual VM shell package membership differs from original compiler")
        packages[name] = expected
    loader = current_files["/lib64/ld-linux-x86-64.so.2"]
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"], "Actual shell loader alias differs")
    tool = protected_host_file(Path("/usr/sbin/ldconfig.real"), 4 << 20)
    static_ldconfig(D.read(Path(tool["path"]), 4 << 20))
    cache = protected_host_file(Path("/etc/ld.so.cache"), 16 << 20)
    D.need(not Path("/etc/ld.so.preload").exists() and not Path("/etc/ld.so.preload").is_symlink(),
           "Ambient loader preload is present")
    return {"libraries": libraries, "programs": programs, "modules": modules, "scripts": scripts,
            "osFiles": current_files, "packages": packages, "moduleRoots": root_bindings, "runtimeData": runtime_data,
            "loader": loader, "ldconfig": tool, "cache": cache, "osNames": sorted(libraries), "graph": native,
            "externalPrerequisites": "Accepted hosted OS/bootstrap and initial mounts; administrator prevents concurrent "
                "native input/cache replacement. This finite GTK/WebKit profile does not qualify arbitrary media, user modules or distribution notices."}


def package_rows(stager, binary_rows, runtime_rows, kit_rows, notice_rows, manifest, version, depends):
    mapping = {}

    def add(name, row, mode):
        D.need(name not in mapping, "Expected package member collision")
        mapping[name] = {"type": "file", "mode": mode, "size": row["size"], "sha256": row["sha256"]}

    for name, destination in stager.BINARIES.items():
        add(destination, binary_rows[name], 0o755)
    prefix = "usr/lib/mobile-release-kit/runtime-input/" + TARGET + "/" + manifest
    for name, row in runtime_rows.items():
        add(prefix + "/" + name, row, 0o555 if name == "python/bin/python3" else 0o444)
    for name, row in kit_rows.items():
        add(stager.DOCS + "/runtime/" + name, row, 0o644)
    for name, row in notice_rows.items():
        add(stager.DOCS + "/desktop/" + name, row, 0o644)
    for name, destination, mode in (("postinst", "DEBIAN/postinst", 0o755), ("prerm", "DEBIAN/prerm", 0o755),
                                   ("postrm", "DEBIAN/postrm", 0o755),
                                   ("mobile-release-kit.desktop", "usr/share/applications/mobile-release-kit.desktop", 0o644),
                                   ("README.md", stager.DOCS + "/INSTALLATION.md", 0o644)):
        add(destination, D.file_record(stager.TEMPLATES / name, 64 << 10), mode)
    installed = (sum(row["size"] for name, row in mapping.items() if not name.startswith("DEBIAN/")) + 1023) // 1024
    control = stager.controls(version, depends, installed)
    add("DEBIAN/control", {"size": len(control), "sha256": hashlib.sha256(control).hexdigest()}, 0o644)
    data_rows, control_rows = {".": {"type": "directory", "mode": 0o755}}, {".": {"type": "directory", "mode": 0o755}}
    for name, row in mapping.items():
        target = control_rows if name.startswith("DEBIAN/") else data_rows
        relative = name.removeprefix("DEBIAN/") if target is control_rows else name
        target[relative] = row
        for parent in Path(relative).parents:
            if str(parent) != ".":
                target[str(parent)] = {"type": "directory", "mode": 0o755}
    return data_rows, control_rows


def package_inputs(source, work, *, fixtures=True):
    """Admit all A bytes and the fixed fresh F1 DATA before compilation."""
    admission = C.CONVENTIONAL_SMOKE_INPUTS
    artifact = work / "admitted-a"
    original = C.conventional_files(D, artifact, admission["preparedArtifact"]["files"])
    D.need(len(original) == 47, "Original A transport roster differs")
    D.unpack(artifact / "prepared-runtime.tar", original["prepared-runtime.tar"], work / "prepared")
    D.need(D.file_record(source / "desktop/tools/stage_ubuntu_deb.py", 64 << 10)["sha256"]
           == "961b95afb5631ec4f7b81b9affa023b2077c0cf50a3752212a1182a6dc39df98", "Accepted stager source differs")
    stager = local("stage_ubuntu_deb")
    p0 = work / "prepared/runtime"
    runtime_rows = stager.runtime_records(p0, admission["manifestSha256"], admission["protocolSha256"])
    D.need(len(runtime_rows) == 607, "Original A runtime roster differs")
    for name, row in runtime_rows.items():
        D.bound(p0 / name, row)
    raw = D.read(p0 / "manifest.json", 1 << 20)
    D.need(len(raw) == 85440 and hashlib.sha256(raw + b"\n").hexdigest() == F1_MANIFEST_SHA256,
           "Fixed F1 trailing-whitespace anchor differs")
    if not fixtures:
        return stager, artifact, original, p0, runtime_rows, None, None, None
    f1 = work / "fixture-runtime"
    f1.mkdir(mode=0o700)
    for name, row in runtime_rows.items():
        if name == "manifest.json":
            continue
        target = f1 / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        D.copy(p0 / name, target, row, stat.S_IMODE((p0 / name).lstat().st_mode))
    D.write(f1 / "manifest.json", raw + b"\n", 0o444)
    f1_rows = stager.runtime_records(f1, F1_MANIFEST_SHA256, admission["protocolSha256"])
    kit = stager.kit_records(artifact, original)
    return stager, artifact, original, p0, runtime_rows, f1, f1_rows, kit


def shell_source_manifest(source):
    manifest = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.toml", 64 << 10).decode("utf-8"))
    features = manifest.get("features", {})
    D.need(features.get("default") == [] and features.get("custom-protocol") == ["tauri/custom-protocol"]
           and features.get("development-runtime") == [], "Shell production feature forwarding differs")
    # The maintained SDK also uses sha2 0.11.0. Bind the complete override map
    # to the application's actual hashing version, without ambiguous names.
    D.need(D.same(manifest.get("profile", {}).get("dev", {}).get("package", {}), {
        "sha2:0.10.9": {"opt-level": 3, "debug-assertions": True, "overflow-checks": True}}),
        "Shell dev profile must preserve complete bounded runtime hashing")
    normal = [row for row in manifest.get("bin", []) if row.get("name") == SHELL_EXPORTS["normal"]]
    observer = [row for row in manifest.get("test", []) if row.get("name") == SHELL_EXPORTS["observer"]]
    D.need(len(normal) == len(observer) == 1 and normal[0].get("path") == "src/main.rs"
           and normal[0].get("required-features") == ["desktop-shell"]
           and observer[0].get("path") == "tests/installed_shell_observation.rs"
           and observer[0].get("harness") is False
           and sorted(observer[0].get("required-features", [])) == SHELL_FEATURES,
           "Normal shell/harness-free observer manifest differs")
    config = D.decode(D.read(source / "desktop/src-tauri/tauri.conf.json", 64 << 10), 64 << 10)
    D.need(config["build"] == {"frontendDist": "../dist"} and config["bundle"]["active"] is False,
           "Shell must embed the fixed frontend, without a dev server or bundle build")
    paths = ("desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock", "desktop/src-tauri/build.rs",
             "desktop/src-tauri/src/main.rs", "desktop/src-tauri/tests/installed_shell_observation.rs",
             "desktop/src-tauri/src/error.rs", "desktop/src-tauri/src/protocol.rs", "desktop/src-tauri/src/installed_runtime.rs",
             "desktop/src-tauri/src/passive_management_tests.rs", "desktop/src-tauri/src/credential_assessment.rs",
             "desktop/src-tauri/src/runtime.rs", "desktop/src-tauri/src/bridge.rs", "desktop/src-tauri/src/asset_session.rs",
             "desktop/src-tauri/src/asset_source.rs", "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/src/installed_shell_observation.rs",
             "desktop/src-tauri/src/supervisor.rs", "desktop/src-tauri/src/installed_shell_shutdown_observation.rs",
             "desktop/src-tauri/src/installed_tools_observation.rs", "desktop/src-tauri/src/environment_diagnostics_owner.rs",
             "desktop/src-tauri/src/environment_diagnostics_protocol.rs", "desktop/src-tauri/src/saved_command_owner.rs",
             "desktop/src-tauri/src/offline_preflight_owner.rs", "desktop/src-tauri/src/offline_preflight_protocol.rs",
             "desktop/src-tauri/tauri.conf.json", "desktop/package.json", "desktop/package-lock.json",
             "desktop/vite.config.mjs", "desktop/tsconfig.json", "desktop/src/App.tsx",
             "desktop/src/components/EnvironmentDiagnostics.tsx", "desktop/tests/environment-diagnostics.test.mjs",
             "desktop/tools/ci_ubuntu_publication.py", "desktop/tools/ubuntu_publication_lifecycle.py",
             "desktop/tools/prepare_hosted_ubuntu_data.py")
    return [{**D.file_record(source / path, 2 << 20), "path": path} for path in sorted(paths)]


def shell_source_status(raw, allowed):
    """Only this job's initially absent generated roots may dirty git status."""
    D.need(type(raw) is bytes and len(raw) <= LOG_LIMIT and set(allowed) <= set(SHELL_GENERATED),
           "Shell generated-source status bound")
    if not raw:
        return
    # Own the newly created parent as well, but only its fixed autogenerated
    # subtree is disposable compiler output. Hand-authored permissions stay source.
    status_roots = tuple(root + "/autogenerated" if root == SHELL_PERMISSIONS else root for root in allowed)
    D.need(raw.endswith(b"\0"), "Incomplete shell source status")
    for item in raw[:-1].split(b"\0"):
        D.need(item.startswith(b"!! "), "Tracked/untracked shell source changed")
        name = item[3:].decode("utf-8").rstrip("/")
        D.relative(name)
        D.need(any(name == root or name.startswith(root + "/") for root in status_roots),
               "Unowned ignored shell source addition")


def shell_generated_tree(path, *, links=False):
    """Inert, bounded generated input/output inventory; no compiler execution."""
    D.directory(path)
    files, aliases, directories, total = [], [], [], 0
    for base, dirs, names in os.walk(path, followlinks=False):
        directory = Path(base)
        for leaf in sorted([*dirs, *names]):
            selected = directory / leaf
            relative = selected.relative_to(path).as_posix()
            D.relative(relative)
            value = selected.lstat()
            D.need(value.st_uid == os.getuid() and (stat.S_ISLNK(value.st_mode) or not value.st_mode & 0o7022),
                   "Generated shell member owner/mode differs")
            if stat.S_ISLNK(value.st_mode):
                # npm's .bin links stay inside this newly generated tree.
                D.need(links and selected.resolve(strict=True).is_relative_to(path)
                       and selected.resolve(strict=True).is_file(), "Generated shell link escapes its input tree")
                target = os.readlink(selected)
                D.need(len(target) <= 4096 and D.state(selected.lstat()) == D.state(value), "Generated shell link changed")
                aliases.append({"path": relative, "target": target})
            elif stat.S_ISDIR(value.st_mode):
                directories.append(relative)
            else:
                D.need(stat.S_ISREG(value.st_mode), "Special generated shell member")
                row = {**D.file_record(selected, 32 << 20), "path": relative}
                files.append(row)
                total += row["size"]
            D.need(len(files) + len(aliases) + len(directories) <= 32768 and total <= 512 << 20,
                   "Generated shell tree bound")
    body = {"files": sorted(files, key=lambda row: row["path"]),
            "links": sorted(aliases, key=lambda row: row["path"]), "directories": sorted(directories)}
    return {"treeSha256": hashlib.sha256(D.canonical(body)).hexdigest(), "files": body["files"],
            "links": body["links"], "directories": body["directories"], "bytes": total}


def shell_permissions_tree(path):
    """Account the entire new parent, without admitting other permission inputs."""
    tree = shell_generated_tree(path)
    D.need("autogenerated" in tree["directories"] and tree["files"]
           and all(name == "autogenerated" or name.startswith("autogenerated/") for name in tree["directories"])
           and all(row["path"].startswith("autogenerated/") for row in tree["files"]),
           "Generated permission parent contains unrelated inputs")
    return tree


def shell_directory_identity(path):
    """Stable directory binding; timestamps/link counts change during removal."""
    D.directory(path)
    value = path.lstat()
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def shell_remove_owned_directory(path, expected, parents, deadline):
    """Retire one known compiler directory through its original no-follow FD.

    Only the four initially absent generated roots and original private work
    call this function, after their original workers have returned. rmtree is
    confined below the opened target, never a fresh lookup of the target path.
    A stalled filesystem call is not made interruptible by endpoint checks;
    any late/uncertain return blocks the next stage rather than claiming cleanup.
    """
    D.need(shutil.rmtree.avoids_symlink_attacks, "FD-relative compiler cleanup is unavailable")
    D.need(path.parent in parents and len(expected) == 5 and expected[3] == os.geteuid()
           and stat.S_ISDIR(expected[2]) and not expected[2] & 0o7022,
           "Unowned compiler cleanup target")
    original_fds, problem = [], None

    def identity(value):
        return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid

    def recheck():
        D.need(time.monotonic() < deadline, "Original compiler cleanup endpoint expired")
        D.need(all(shell_directory_identity(parent) == wanted for parent, wanted in parents.items()),
               "Original compiler cleanup ancestry changed")

    try:
        recheck()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent_fd = os.open(path.parent, flags)
        original_fds.append(parent_fd)
        D.need(identity(os.fstat(parent_fd)) == parents[path.parent], "Compiler cleanup parent binding changed")
        D.need(identity(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) == expected,
               "Original compiler cleanup directory was replaced")
        target_fd = os.open(path.name, flags, dir_fd=parent_fd)
        original_fds.append(target_fd)
        D.need(identity(os.fstat(target_fd)) == expected, "Compiler cleanup original open differs")
        entries = sorted(os.listdir(target_fd))
        D.need(len(entries) <= 32768, "Compiler cleanup direct-entry bound")
        # Precheck the complete direct roster before deleting any entry. The
        # generated trees additionally have full byte inventories at the caller.
        entries = [(name, os.stat(name, dir_fd=target_fd, follow_symlinks=False)) for name in entries]
        D.need(all(value.st_uid == os.geteuid() and value.st_dev == expected[0]
                   and (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode))
                   for _, value in entries), "Unowned or nonordinary compiler cleanup member")
        for name, value in entries:
            recheck()
            D.need(identity(os.fstat(parent_fd)) == parents[path.parent]
                   and identity(os.fstat(target_fd)) == expected
                   and identity(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) == expected,
                   "Compiler cleanup original binding changed")
            D.need(D.state(os.stat(name, dir_fd=target_fd, follow_symlinks=False)) == D.state(value),
                   "Compiler cleanup member changed before removal")
            if stat.S_ISDIR(value.st_mode):
                shutil.rmtree(name, dir_fd=target_fd)
            else:
                os.unlink(name, dir_fd=target_fd)
        recheck()
        D.need(os.listdir(target_fd) == [] and identity(os.fstat(target_fd)) == expected
               and identity(os.fstat(parent_fd)) == parents[path.parent]
               and identity(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) == expected,
               "Original compiler cleanup directory is not empty/bound")
        os.rmdir(path.name, dir_fd=parent_fd)
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise D.Refused("Compiler cleanup name remains present")
        D.need(os.fstat(target_fd).st_nlink == 0, "Original compiler cleanup directory remains linked")
        recheck()
    except BaseException as error:
        problem = error
    # Retire every original once, retaining the first error. Neither Drop nor
    # a later successful lookup can replace a failed consuming close.
    for fd in reversed(original_fds):
        try:
            os.close(fd)
        except BaseException as error:
            if problem is None:
                problem = error
    if problem is not None:
        raise problem
    D.need(time.monotonic() < deadline, "Original compiler cleanup closed late")


def shell_cargo_metadata(raw, source, target):
    """Validate the actual full Cargo graph, not a remembered Tauri subset."""
    metadata = C.bounded_json(raw, SHELL_METADATA_LIMIT, max_nodes=200000)
    packages, resolve = metadata.get("packages"), metadata.get("resolve")
    D.need(type(packages) is list and 36 <= len(packages) <= 512 and type(resolve) is dict
           and metadata.get("workspace_root") == str(source / "desktop/src-tauri")
           and metadata.get("target_directory") == str(target), "Shell Cargo metadata root/count differs")
    by_id = {row["id"]: row for row in packages}
    nodes = {row["id"]: row for row in resolve["nodes"]}
    D.need(len(by_id) == len(packages) and len(nodes) == len(resolve["nodes"])
           and set(nodes) <= set(by_id), "Shell Cargo metadata IDs differ/duplicate")
    roots = [row for row in packages if row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")]
    D.need(len(roots) == 1 and roots[0]["name"] == "mobile-release-kit-desktop" and roots[0]["version"] == "0.1.0"
           and resolve.get("root") == roots[0]["id"] and roots[0]["id"] in nodes
           and nodes[roots[0]["id"]]["features"] == SHELL_FEATURES,
           "Shell root feature graph is not the fixed production graph")
    for row in nodes.values():
        D.need(type(row.get("features")) is list and all(type(name) is str for name in row["features"])
               and type(row.get("deps")) is list and all(dep.get("pkg") in nodes for dep in row["deps"]),
               "Shell resolved Cargo edge/features differ")
    local_paths = linux_local_cargo_sources(packages, nodes, roots[0], source)
    registry = [row for row in packages if row.get("source") is not None]
    keys = {(row["name"], row["version"]) for row in registry}
    D.need(len(keys) == len(registry) and all(row["name"] not in local_paths
           and row["source"] == "registry+https://github.com/rust-lang/crates.io-index"
           and re.fullmatch(r"[A-Za-z0-9_-]+", row["name"]) is not None
           and re.fullmatch(r"[0-9][A-Za-z0-9.+_-]+", row["version"]) is not None for row in registry),
           "Shell Cargo registry/source identity differs")
    D.need({("tauri", "2.11.5"), ("tauri-build", "2.6.3"), ("gtk", "0.18.2"),
            ("webkit2gtk", "2.0.2"), ("wry", "0.55.1"), ("rfd", "0.15.4")} <= keys,
           "Actual shell backend is missing from Cargo metadata")
    tauri = [row for row in registry if row["name"] == "tauri"]
    D.need(len(tauri) == 1 and {"custom-protocol", "wry", "compression"} <= set(nodes[tauri[0]["id"]]["features"]),
           "Tauri is not the embedded production WebKit backend")
    return metadata, by_id, nodes


def shell_compiler_units(units, packages, nodes):
    D.need(all(row["package_id"] in packages and row["package_id"] in nodes
               and set(row["features"]) <= set(nodes[row["package_id"]]["features"]) for row in units),
           "Compiler used a package/feature outside original full shell metadata")
    hashing = [row for row in units if (packages[row["package_id"]]["name"], packages[row["package_id"]]["version"])
               == ("sha2", "0.10.9") and row["target"].get("kind") == ["lib"]]
    D.need(hashing and all(row["profile"].get("opt_level") == "3"
                          and row["profile"].get("debug_assertions") is True
                          and row["profile"].get("overflow_checks") is True for row in hashing),
           "Original shell sha2 unit lost its reviewed optimized full-hashing profile")


def shell_compiler_inputs(source, work, cargo, rustc, metadata_raw):
    metadata, by_id, nodes = shell_cargo_metadata(metadata_raw, source, work / "target")
    lock = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.lock", 256 << 10).decode("utf-8"))
    locked = {(row["name"], row["version"]): row for row in lock["package"] if "source" in row}
    crates, inputs = [], []
    for package in sorted(metadata["packages"], key=lambda row: (row["name"], row["version"])):
        if package["source"] is None:
            continue
        key = package["name"], package["version"]
        D.need(key in locked and locked[key]["source"] == package["source"], "Actual shell crate is absent from lockfile")
        candidates = list((work / "cargo/registry/cache").glob("*/" + key[0] + "-" + key[1] + ".crate"))
        D.need(len(candidates) == 1, "Actual shell crate archive is missing/ambiguous")
        record = {**D.file_record(candidates[0], 16 << 20), "path": str(candidates[0])}
        D.need(record["sha256"] == D.sha(locked[key]["checksum"]), "Actual shell crate differs from locked original")
        inputs.append(record)
        crates.append({"name": key[0], "version": key[1], "packageId": package["id"],
                       "archive": record, "features": nodes.get(package["id"], {}).get("features", []),
                       "licenseMetadata": package.get("license")})
    toolchain = Path(rustc).parent.parent
    D.need(Path(cargo).parent.parent == toolchain and toolchain.is_relative_to(work / "rustup/toolchains"),
           "Shell private compiler component root differs")
    manifest = toolchain / "lib/rustlib/multirust-channel-manifest.toml"
    channel = tomllib.loads(D.read(manifest, 2 << 20).decode("utf-8"))
    pinned = {"rustc": "0e37cb339f447fc44d6d781073bacacebfdc5612f2600e4c7e84c266f5f3aced",
              "rust-std": "f5022e6c95a5ad23cca2513dc8281200f585fa188de6370aa37b128a43f876a3"}
    for component, digest in pinned.items():
        D.need(channel["pkg"][component]["version"] == "1.98.0 (88d9e12ae 2026-08-18)"
               and channel["pkg"][component]["target"][TARGET]["xz_hash"] == digest,
               "Shell original Rust component identity differs")
    manifests, members = [manifest], {}
    for component in ("rustc", "rust-std", "cargo"):
        path = toolchain / "lib/rustlib" / ("manifest-" + component + "-" + TARGET)
        lines = D.read(path, 128 << 10).decode("ascii").splitlines()
        D.need(0 < len(lines) <= 512 and all(line.startswith("file:") for line in lines),
               "Shell Rust component manifest differs")
        names = [D.relative(line.removeprefix("file:")) for line in lines]
        D.need(len(names) == len(set(names)), "Duplicate shell Rust component member")
        members[component] = set(names)
        manifests.append(path)
    prefix = "lib/rustlib/" + TARGET + "/lib/"
    std = members["rust-std"]
    D.need(all(name.startswith(prefix) and Path(name).suffix in (".rlib", ".rmeta", ".a", ".o", ".so") for name in std)
           and any(Path(name).name.startswith("libstd-") and name.endswith(".rlib") for name in std)
           and any(Path(name).name.startswith("libcompiler_builtins-") and name.endswith(".rlib") for name in std)
           and {str(path.relative_to(toolchain)) for path in (toolchain / prefix).iterdir() if not path.is_dir()} == std,
           "Shell Rust standard/static support roster differs")
    compiler = {"bin/rustc", "lib/rustlib/" + TARGET + "/bin/rust-lld", "lib/rustlib/" + TARGET + "/bin/gcc-ld/ld.lld"}
    compiler |= {name for name in members["rustc"] if name.startswith("lib/libLLVM") or name.startswith("lib/librustc_driver-")}
    D.need(len(compiler) >= 5 and compiler <= members["rustc"] and "bin/cargo" in members["cargo"],
           "Shell Rust compiler/linker component missing")
    for path in [*manifests, *(toolchain / name for name in sorted(compiler | std | {"bin/cargo"}))]:
        inputs.append({**D.file_record(path, MAX_BINARY), "path": str(path)})
    D.need(sum(row["size"] for row in inputs) <= 1536 << 20, "Shell compiler/component input bound")
    return {"scope": "Actual compile inputs; not a distribution notice union or licensing completeness claim.",
            "crates": crates, "files": inputs, "metadataSha256": hashlib.sha256(metadata_raw).hexdigest(),
            "rust": {"version": C.RUST, "commit": "88d9e12ae178fab0fb5cc050a94da85685d449ea",
                     "components": pinned, "cargoArchiveSha256": D.sha(channel["pkg"]["cargo"]["target"][TARGET]["xz_hash"])}}, by_id


def shell_module_inventory():
    roots, bindings, selected = {}, {}, []
    for name in SHELL_MODULE_ROOTS:
        path = Path(name)
        binding = shell_host_binding(path, directory_only=True, absent=True)
        children = [] if binding.get("absent") else sorted(child.name for child in path.iterdir())
        D.need(len(children) <= 256 and all(re.fullmatch(r"[A-Za-z0-9_.+\-]+", child) for child in children),
               "Fixed shell module directory bound/grammar")
        cache = [child for child in children if name == SHELL_LIBRARY_ROOT + "/gio/modules" and child == "giomodule.cache"]
        modules = [child for child in children if child not in cache]
        D.need(all(child.endswith(".so") for child in modules), "Unreviewed shell module directory member")
        roots[name] = {"present": not binding.get("absent", False), "modules": modules}
        bindings[name] = {"binding": binding, "children": children}
        selected.extend(str(path / child) for child in modules)
        D.need(D.same(shell_host_binding(path, directory_only=True, absent=True), binding)
               and (binding.get("absent") or sorted(child.name for child in path.iterdir()) == children),
               "Fixed shell module directory changed while listing")
    D.need(1 <= len(selected) <= 256, "Actual shell module roster bound")
    return roots, bindings, sorted(selected)


def shell_data_records(snapshot, public, prefix):
    records = []
    for index, (_, detail) in enumerate(snapshot["details"].items()):
        leaf = prefix + "-" + str(index) + ".json"
        raw = D.canonical(detail)
        D.need(len(raw) <= 2 << 20, "Fixed shell DATA root detail bound")
        records.append({**D.write(public / leaf, raw), "path": leaf})
    return {key: snapshot[key] for key in ("suppliers", "caches", "moduleSelections", "eglLibraries")} | {"records": records}


def shell_private_search(records, libraries):
    """Portable per-requester search candidates, including private hwcaps."""
    result = []
    for row in records:
        path, elf = row["file"]["selectedPath"], row["elf"]
        if "runpath" not in elf:
            continue
        D.need(path in SHELL_RUNPATHS and (elf["soname"], elf["runpath"]) == SHELL_RUNPATHS[path],
               "Unadmitted shell requester RUNPATH")
        if path.endswith("/libLLVM.so.20.1"):
            D.need(row["file"]["path"] == path, "LLVM ORIGIN provider is not its fixed direct package member")
        for directory in SHELL_RUNPATH_DIRECTORIES[path]:
            for name in elf["needed"]:
                selected = shell_provider_path(path, elf["runpath"], name)
                D.need(selected == libraries[name]["file"]["selectedPath"], "Shell edge resolves to another provider")
                for prefix in ("", *("glibc-hwcaps/" + tier + "/" for tier in ("x86-64-v4", "x86-64-v3", "x86-64-v2"))):
                    candidate = str(Path(directory) / (prefix + name))
                    result.append({"requester": path, "runpath": elf["runpath"], "name": name,
                                   "path": candidate, "selected": candidate == selected})
    return sorted(result, key=lambda row: (row["requester"], row["path"]))


def shell_package_members(stdout, stderr):
    """Declared members, not the destinations of dpkg's directory annotations."""
    lines = stdout.decode("utf-8").splitlines()
    D.need(stderr == b"" and 0 < len(lines) <= 32768, "Shell native package member roster differs")
    members, annotated, previous = set(), set(), None
    for line in lines:
        if line.startswith("/"):
            D.need(".." not in Path(line).parts, "Shell native package member roster differs")
            members.add(line)
            previous = line
        else:
            D.need(previous in {"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}
                   and previous not in annotated
                   and line == "diverted by base-files to: " + previous + ".usr-is-merged",
                   "Shell native package has unsupported or repeated directory diversion metadata")
            # Keep the original declared directory. This line grants no file or
            # supplier authority, and its destination is never followed/admitted.
            annotated.add(previous)
            previous = None
    return members


def shell_package_owner(row, package_files, query, admit):
    """Keep a selected link's supplier separate from its canonical provider.

    Callbacks retain the existing command owner and complete package captures.
    This resolver only compares bounded DATA; it cannot admit an executable.
    """
    def spellings(path):
        names = {path}
        if path.startswith("/usr/lib/"):
            names.add(path.removeprefix("/usr"))
        elif path.startswith("/lib/"):
            names.add("/usr" + path)
        return names

    canonical, selected = spellings(row["path"]), spellings(row["selectedPath"])
    aliases = canonical | selected

    def members():
        mapping = {}
        for name, paths in package_files.items():
            for path in aliases & paths:
                D.need(path not in mapping, "Shell native member has two admitted suppliers")
                mapping[path] = name
        for group in (canonical, selected):
            D.need(len({mapping[path] for path in group if path in mapping}) <= 1,
                   "Shell native usr-merge name has ambiguous suppliers")
        return mapping

    known = members()
    canonical_owners = {known[path] for path in canonical if path in known}
    # A canonical cache hit alone must not omit an unqueried link supplier.
    if canonical_owners and (canonical & selected or selected & known.keys()):
        return next(iter(canonical_owners))

    stdout, stderr = query(sorted(aliases))
    reported, missing, diverted = {}, set(), {}
    pending = None
    for line in stdout.decode("ascii").splitlines():
        diversion = re.fullmatch(r"diversion by ([a-z0-9][a-z0-9+.-]+) (from|to): (.+)", line)
        if diversion:
            name, direction, path = diversion.groups()
            if direction == "from":
                D.need(pending is None and path.startswith("/lib/") and path in aliases and "/usr" + path in aliases
                       and path not in reported and path not in diverted,
                       "Shell usr-merge diversion source is unrelated, repeated or conflicting")
                pending = (name, path)
            else:
                D.need(pending is not None and (name, path) == (pending[0], pending[1] + ".usr-is-merged"),
                       "Shell usr-merge diversion target has no exact paired source")
                # This is only query metadata. Never follow or admit its target.
                diverted[pending[1]] = pending[0]
                pending = None
            continue
        D.need(pending is None, "Shell usr-merge diversion pair is incomplete")
        name, separator, path = line.rpartition(": ")
        D.need(separator and path in aliases and path not in reported and path not in diverted
               and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name),
               "Shell native ownership query contains an unrelated or duplicate member")
        reported[path] = name
    D.need(pending is None, "Shell usr-merge diversion pair is incomplete")
    prefix = "dpkg-query: no path found matching pattern "
    for line in stderr.decode("ascii").splitlines():
        path = line.removeprefix(prefix)
        D.need(line.startswith(prefix) and path in aliases and path not in missing and path not in reported and path not in diverted,
               "Unexpected or conflicting shell ownership query diagnostic")
        missing.add(path)
    D.need(set(reported) | missing | set(diverted) == aliases and all(reported.get(path) == name for path, name in known.items()),
           "Shell native ownership query is incomplete or changed an admitted member")
    for name in sorted(set(reported.values())):
        admit(name)
    D.need(all(path in package_files[name] for path, name in reported.items()) and members() == reported,
           "Shell native file is absent from its own package roster")
    D.need(all("/usr" + path in reported and reported["/usr" + path].split(":")[0] == name for path, name in diverted.items()),
           "Shell usr-merge diversion is not bound to its actual admitted supplier")
    canonical_owners = {reported[path] for path in canonical if path in reported}
    D.need(len(canonical_owners) == 1, "Shell canonical provider ownership is missing/ambiguous")
    return next(iter(canonical_owners))


def shell_native_inputs(check, work, environment):
    """Fresh shell-only static provider closure; never a widened J/U allowlist.

    Provider names come from actual ELF edges of the fixed GTK/WebKit seeds,
    subprocesses, finite module roots and protected EGL selectors. This is a
    bounded current-job profile, not a distribution notice/licensing union.
    """
    files, packages, package_files, libraries, programs, modules, scripts = {}, {}, {}, {}, {}, {}, {}
    counter = 0

    def host(path, limit=MAX_BINARY):
        check.phase = "shell-native-file:" + str(path)
        row = protected_host_file(Path(path), limit)
        files[row["selectedPath"]] = row
        D.need(len(files) <= 512 and sum({item["path"]: item["size"] for item in files.values()}.values()) <= 2 << 30,
               "Shell native input file/byte bound")
        return row

    def package(name):
        nonlocal counter
        D.need(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name) is not None, "Shell native package name differs")
        if name in packages:
            return
        D.need(len(packages) < 256, "Shell package closure bound")
        counter += 1
        fields = "${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
        argv = ["/usr/bin/dpkg-query", "-W", "-f=" + fields, name]
        result = check.command("shell-package-" + str(counter), argv, environment, work, timeout=15, limit=64 << 10)
        values = result.stdout.decode("ascii").rstrip("\n").split("\t")
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and len(values) == 6
               and values[0].split(":")[0] == name.split(":")[0] and values[1] == "installed"
               and values[3] in {"amd64", "all"} and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", values[4]) is not None
               and all(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", values[i]) for i in (2, 5)),
               "Actual shell native package tuple differs")
        listing = check.command("shell-package-files-" + str(counter), ["/usr/bin/dpkg-query", "-L", name],
                                environment, work, timeout=15, limit=1 << 20)
        paths = shell_package_members(listing.stdout, listing.stderr)
        packages[name] = {"binaryPackage": values[0], "version": values[2], "architecture": values[3],
                          "sourcePackage": values[4], "sourceVersion": values[5], "queryArgv": argv,
                          "querySha256": hashlib.sha256(result.stdout).hexdigest(),
                          "memberQuerySha256": hashlib.sha256(listing.stdout).hexdigest()}
        package_files[name] = paths

    def owner(row):
        nonlocal counter
        counter += 1
        def query(aliases):
            result = check.command("shell-file-owner-" + str(counter), ["/usr/bin/dpkg-query", "-S", *aliases],
                                   environment, work, timeout=15, codes=(0, 1), limit=64 << 10)
            return result.stdout, result.stderr
        return shell_package_owner(row, package_files, query, package)

    tools = {name: host(path) for name, path in (("cc", "/usr/bin/cc"), ("pkgConfig", "/usr/bin/pkg-config"),
                                              ("ldconfig", "/usr/sbin/ldconfig.real"))}
    static_ldconfig(D.read(Path(tools["ldconfig"]["path"]), 4 << 20))
    for row in tools.values():
        owner(row)
    gcc = check.command("shell-gcc-version", ["/usr/bin/cc", "-dumpfullversion"], environment, work, timeout=15, limit=4096)
    D.need(gcc.stderr == b"" and re.fullmatch(rb"[0-9]+(?:\.[0-9]+){1,2}\n", gcc.stdout), "Shell GNU compiler version differs")
    for kind, names in (("program", ("collect2", "ld")),
                        ("support", ("Scrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o", "libgcc.a",
                                     "libgcc_eh.a", "libgcc_s.so", "libc.so", "libc_nonshared.a", "libutil.a",
                                     "librt.a", "libpthread.a", "libm.so", "libdl.a"))):
        for index, name in enumerate(names):
            option = "-print-prog-name=" if kind == "program" else "-print-file-name="
            result = check.command("shell-gcc-" + kind + "-" + str(index), ["/usr/bin/cc", option + name],
                                   environment, work, timeout=15, limit=4096)
            D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Shell GNU standard component query differs")
            path = result.stdout.decode("ascii").rstrip("\n")
            if not path.startswith("/") and kind == "program":
                path = shutil.which(path, path="/usr/bin:/bin")
            D.need(path is not None and path.startswith("/"), "Shell GNU standard component did not resolve")
            owner(host(os.path.abspath(path)))
    pkg_config = {}
    for label, argv in (
        ("versions", ["/usr/bin/pkg-config", "--modversion", "gtk+-3.0", "webkit2gtk-4.1"]),
        ("flags", ["/usr/bin/pkg-config", "--cflags", "--libs", "gtk+-3.0", "webkit2gtk-4.1"]),
    ):
        result = check.command("shell-pkg-config-" + label, argv, environment, work, timeout=15, limit=64 << 10)
        D.need(result.stderr == b"" and 0 < len(result.stdout) <= 64 << 10, "Shell GTK/WebKit package-config result differs")
        pkg_config[label] = result.stdout.decode("utf-8")
    D.need(len(pkg_config["versions"].splitlines()) == 2
           and all(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", row) for row in pkg_config["versions"].splitlines()),
           "Shell GTK/WebKit package-config versions differ")
    lifecycle = local("ubuntu_publication_lifecycle")
    check.phase = "shell-runtime-data"
    snapshot = lifecycle.shell_data_snapshot(shell_host_binding)
    runtime_data = shell_data_records(snapshot, check.root / "public", "shell-data")
    check.phase = "shell-module-roots"
    roots, root_bindings, module_paths = shell_module_inventory()
    D.need(all(set(names) <= set(module_paths) for names in snapshot["moduleSelections"].values()),
           "Current module catalogue selects an unadmitted module")
    seeds = set(SONAME_PACKAGES) | {"libgtk-3.so.0", "libwebkit2gtk-4.1.so.0",
        "libjavascriptcoregtk-4.1.so.0", "libsoup-3.0.so.0", "libGLX_mesa.so.0", "libgbm.so.1"}
    seeds.update(Path(path).name for path in snapshot["eglLibraries"].values())
    pending = {(None, None, name) for name in seeds}

    def edges(path, elf):
        pending.update((path, elf.get("runpath"), name) for name in elf["needed"])

    for path in SHELL_PROGRAMS:
        row = host(path)
        check.phase = "shell-native-program:" + path
        D.need(Path(row["path"]).lstat().st_mode & stat.S_IXUSR, "Shell subprocess is not an executable")
        elf = shell_elf_record(D.read(Path(row["path"]), MAX_BINARY), role="program", selected=path)
        D.need(elf["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and elf["soname"] is None,
               "Shell subprocess ELF kind differs")
        programs[path] = {"file": shell_file_projection(row), "elf": elf, "package": owner(row)}
        edges(path, elf)
    for path in SHELL_SCRIPTS:
        row = host(path, 64 << 10)
        raw = D.read(Path(row["path"]), 64 << 10)
        D.need(raw.startswith(b"#!/bin/sh\n") and row["identity"][2] & stat.S_IXUSR,
               "Fixed Xvfb wrapper script/shebang differs")
        scripts[path] = {"file": shell_file_projection(row), "package": owner(row), "interpreter": "/bin/sh"}
    for path in module_paths:
        row = host(path)
        check.phase = "shell-native-module:" + path
        elf = shell_elf_record(D.read(Path(row["path"]), MAX_BINARY), role="module", selected=path)
        D.need(elf["interpreter"] is None and (elf["soname"] is None or re.fullmatch(r"[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_.+-]+)?", elf["soname"])),
               "Fixed shell module ELF kind/SONAME differs")
        modules[path] = {"file": shell_file_projection(row), "elf": elf, "package": owner(row)}
        edges(path, elf)
    while pending:
        requester, runpath, name = min(pending, key=lambda edge: (edge[2], edge[0] or "", edge[1] or ""))
        pending.remove((requester, runpath, name))
        check.phase = "shell-native-provider:" + name
        path = shell_provider_path(requester, runpath, name)
        if name in libraries:
            D.need(libraries[name]["file"]["selectedPath"] == path, "Shell SONAME has two different provider contexts")
            continue
        D.need(len(libraries) < SHELL_MAX_LIBRARIES, "Shell static shared-object closure bound")
        row = host(path)
        check.phase = "shell-native-provider:" + path
        elf = shell_elf_record(D.read(Path(row["path"]), MAX_BINARY), role="provider", selected=path)
        D.need(elf["soname"] == name, "Shell provider SONAME differs")
        libraries[name] = {"file": shell_file_projection(row), "elf": elf, "package": owner(row)}
        edges(path, elf)
    loader = host("/lib64/ld-linux-x86-64.so.2")
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"], "Shell interpreter provider differs")
    for record in [*libraries.values(), *programs.values(), *modules.values()]:
        for name, required in record["elf"]["versionNeeds"].items():
            check.phase = "shell-native-version:" + record["file"]["selectedPath"] + "->" + name
            D.need(set(required) <= set(libraries[name]["elf"]["versionDefinitions"]),
                   "Shell native provider lacks a required symbol-version label")
    private_search = shell_private_search([*libraries.values(), *programs.values(), *modules.values()], libraries)
    search_bindings = {}
    for row in private_search:
        current = shell_host_binding(Path(row["path"]), absent=True)
        if row["selected"]:
            D.need(not current.get("absent") and shell_file_projection(current) == libraries[row["name"]]["file"],
                   "Private shell RUNPATH selected another provider")
        else:
            D.need(current.get("absent") is True, "Private shell RUNPATH has an unadmitted search alternative")
        search_bindings[row["path"]] = current
    bindings = {"files": files, "moduleRoots": root_bindings, "privateSearch": search_bindings}
    native = {"scope": "Fixed current-job GTK/WebKit/helper/module/DATA inputs; not general media or distribution qualification.",
              "osFiles": {path: shell_file_projection(row) for path, row in files.items()}, "osPackages": packages,
              "sharedObjects": libraries, "programs": programs, "scripts": scripts, "modules": modules,
              "moduleRoots": roots, "privateSearch": private_search, "runtimeData": runtime_data,
              "loader": shell_file_projection(loader), "gccVersion": gcc.stdout.decode("ascii").strip(), "pkgConfig": pkg_config}
    return native, bindings


def finish_shell_native_inputs(native, outputs, bindings):
    D.need(set(outputs) == set(SHELL_EXPORTS), "Fixed shell output roles differ")
    libraries, records = native["sharedObjects"], {}
    for role, path in outputs.items():
        file = {**D.file_record(path, MAX_BINARY), "path": str(path)}
        elf = shell_elf_record(D.read(path, MAX_BINARY), role=role)
        D.need(elf["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and elf["soname"] is None,
               "Original shell " + role + " output is not the expected dynamically linked executable")
        for name in elf["needed"]:
            D.need(name in libraries and shell_provider_path(None, None, name) == libraries[name]["file"]["selectedPath"],
                   "Actual shell " + role + " has a nonglobal direct dependency: " + name)
        pending, names = set(elf["needed"]) | {"ld-linux-x86-64.so.2"}, set()
        for name, required in elf["versionNeeds"].items():
            D.need(name in libraries and set(required) <= set(libraries[name]["elf"]["versionDefinitions"]),
                   "Actual shell " + role + " requires a different native symbol-version provider: " + name)
        while pending:
            name = pending.pop()
            D.need(name in libraries, "Actual shell " + role + " has an unbound provider: " + name)
            if name not in names:
                names.add(name)
                pending.update(set(libraries[name]["elf"]["needed"]) - names)
        records[role] = {"file": file, "elf": elf, "objects": sorted(names)}
    for path, row in bindings["files"].items():
        D.need(D.same(protected_host_file(Path(path)), row), "Original shell native input changed during compilation")
    roots, current, _ = shell_module_inventory()
    D.need(D.same(roots, native["moduleRoots"]) and D.same(current, bindings["moduleRoots"]),
           "Original shell module directory changed during compilation")
    for path, row in bindings["privateSearch"].items():
        D.need(D.same(shell_host_binding(Path(path), absent=True), row), "Original private shell search candidate changed")
    snapshot = local("ubuntu_publication_lifecycle").shell_data_snapshot(shell_host_binding)
    D.need(all(D.same(snapshot[key], native["runtimeData"][key]) for key in
               ("suppliers", "caches", "moduleSelections", "eglLibraries"))
           and len(snapshot["details"]) == len(native["runtimeData"]["records"]),
           "Original protected shell DATA profile changed during compilation")
    for detail, expected in zip(snapshot["details"].values(), native["runtimeData"]["records"]):
        raw = D.canonical(detail)
        D.need(len(raw) == expected["size"] and hashlib.sha256(raw).hexdigest() == expected["sha256"],
               "Original protected shell DATA identity/membership changed during compilation")
    return {**native, "outputs": records}


def shell_runtime_graph(runtime, rows, shared_objects):
    """A's already-admitted three ELF objects, separate from the shell graph."""
    objects = {}
    for name in RUNTIME_ELF:
        expected = rows[name]
        raw = D.read(runtime / name, 64 << 20)
        D.need(len(raw) == expected["size"] and hashlib.sha256(raw).hexdigest() == expected["sha256"],
               "Original A ELF bytes differ from the complete admitted runtime")
        objects[name] = {"file": expected, "elf": elf_dependencies(raw, runtime_path=name)}
    libraries = {name: row for name, row in shared_objects.items() if name in SONAME_PACKAGES}
    libraries.update({row["elf"]["soname"]: row for name, row in objects.items() if name != "python/bin/python3"})
    names, pending = {"ld-linux-x86-64.so.2"}, [objects["python/bin/python3"]["elf"],
                                             libraries["ld-linux-x86-64.so.2"]["elf"]]
    while pending:
        elf = pending.pop()
        for name in elf["needed"]:
            D.need(name in libraries, "Unbound original A dependency")
            provider = libraries[name]["elf"]
            D.need(set(elf["versionNeeds"].get(name, [])) <= set(provider["versionDefinitions"]),
                   "Original A dependency lacks its required version label")
            if name not in names:
                names.add(name)
                pending.append(provider)
    D.need(names == {"ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libssl.so.3", "libcrypto.so.3"},
           "Original A private/system native graph differs")
    startup = {prefix + name for prefix in ("", "python/", "python/bin/")
               for name in ("pyvenv.cfg", "python3._pth", "pybuilddir.txt")}
    D.need(not startup & set(rows) and not any(name.startswith("python/lib/glibc-hwcaps/") for name in rows)
           and all("python/lib/" + name not in rows for name in names - {"libssl.so.3", "libcrypto.so.3"})
           and {name for name in rows if re.search(r"\.so(?:\.[0-9]+)*$", name)}
               == {"python/lib/libssl.so.3", "python/lib/libcrypto.so.3"},
           "Original A startup/native search alternatives differ")
    return {"manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
            "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"],
            "runtime": objects, "runtimeObjects": sorted(names),
            "privateRunpaths": {name: row[1] for name, row in RUNTIME_ELF.items()}}


def prepare_packages(check, source, work, public, environment, binaries, native_notices, depends, prepared):
    stager, artifact, original, p0, runtime_rows, f1, f1_rows, kit = prepared
    admission = C.CONVENTIONAL_SMOKE_INPUTS
    prepared_pin = D.write(work / "prepared-files.json", D.canonical(list(original.values())))
    notice_pin = D.write(work / "native-notice-files.json", D.canonical(native_notices))
    notice_rows = D.records(native_notices)
    packages, readbacks = {}, {}
    for label, runtime, rows, manifest, version in (
        ("P0", p0, runtime_rows, admission["manifestSha256"], "0.0.0+mrk.lifecycle.0"),
        ("F1", f1, f1_rows, F1_MANIFEST_SHA256, "0.0.0+mrk.lifecycle.1"),
    ):
        compiled = work / ("compiled-" + label)
        compiled.mkdir(mode=0o700)
        records = []
        for name, input_ in (("mobile-release-kit-desktop", binaries["fixture"]), ("mrk-runtime-publish", binaries[label])):
            row = D.file_record(input_, MAX_BINARY)
            D.copy(input_, compiled / name, row, 0o555)
            records.append({**row, "path": name})
        records.sort(key=lambda row: row["path"])
        compiler_pin = D.write(work / (label + "-compiler-files.json"), D.canonical(records))
        output = work / ("stage-" + label)
        argv = ["/usr/bin/python3.12", "-I", "-S", "-B", str(source / "desktop/tools/stage_ubuntu_deb.py")]
        values = {"compiled": compiled, "compiler-files": work / (label + "-compiler-files.json"),
                  "compiler-files-sha256": compiler_pin["sha256"], "runtime": runtime,
                  "prepared-artifact": artifact, "prepared-files": work / "prepared-files.json",
                  "prepared-files-sha256": prepared_pin["sha256"], "desktop-notices": work / "native-notices",
                  "desktop-notice-files": work / "native-notice-files.json", "desktop-notice-files-sha256": notice_pin["sha256"],
                  "manifest-sha256": manifest, "protocol-sha256": admission["protocolSha256"],
                  "version": version, "depends": depends, "output": output}
        for key, value in values.items():
            argv.extend(["--" + key, str(value)])
        result = check.command("stage-" + label, argv, environment, work, timeout=120)
        staged = C.bounded_json(result.stdout, 16384)
        D.need(result.stderr == b"" and staged.get("runtimeManifestSha256") == manifest
               and staged.get("installed") is False and staged.get("qualified") is False, "Original stager result differs")
        # Only this fresh private stage root, never an existing OS parent.
        D.need(output.lstat().st_uid == os.geteuid() and stat.S_IMODE(output.lstat().st_mode) == 0o700,
               "Fresh staging root changed")
        os.chmod(output, 0o755)
        package_path = public / (label + ".deb")
        check.command("deb-build-" + label, ["/usr/bin/dpkg-deb", "--root-owner-group", "--uniform-compression", "-Znone",
                                            "--build", str(output), str(package_path)], environment, work, timeout=120)
        check.phase = "deb-complete-readback-" + label
        expected_data, expected_control = package_rows(stager, D.records(records), rows, kit, notice_rows, manifest, version, depends)
        readback = deb_readback(package_path, expected_data, expected_control)
        packages[label] = {key: readback[key] for key in ("path", "size", "sha256")}
        packages[label].update(manifestSha256=manifest, version=version)
        readbacks[label] = {**readback, "dataRows": expected_data, "controlRows": expected_control}
    D.write(public / "package-members.txt", D.canonical(readbacks))
    capacity = {"runtimeBytes": sum(row["size"] for row in runtime_rows.values()),
                "installedBytes": {name: row["data.tar"]["bytes"] for name, row in readbacks.items()},
                "installedEntries": {name: row["data.tar"]["entries"] for name, row in readbacks.items()}}
    return packages, capacity


def verify_installed_shell_compile():
    D.need(os.environ.get("MRK_INSTALLED_SHELL_CASE") == "compile" and "MRK_INSTALLED_CASE" not in os.environ,
           "Fixed production shell compiler route differs")
    sha, source, temporary, root, deadline = resumed_preparation()
    os.umask(0o077)
    work, public = root / "work", root / "public"
    identities = {str(path): directory_identity(path) for path in (root, work, public, root / "cases")}
    cleanup_paths = {parent for path in (root, source, source / "desktop", source / "desktop/src-tauri")
                     for parent in (path, *path.parents)}
    cleanup_parents = {path: shell_directory_identity(path) for path in sorted(cleanup_paths)}
    sys.path.insert(0, str(source / "src"))
    from mobile_release.owned_process import run_owned
    check = Check(root, run_owned, deadline=deadline)
    environment = C.clean_environment(work)
    environment.update(CARGO_TARGET_DIR=str(work / "target"), CC="/usr/bin/cc", CXX="/usr/bin/c++",
                       PKG_CONFIG="/usr/bin/pkg-config", CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="/usr/bin/cc")
    git = shutil.which("git", path=environment["PATH"])
    rustup = shutil.which("rustup", path=environment["PATH"])
    node = shutil.which("node", path=environment["PATH"])
    generated, source_inputs, permissions = {}, None, None

    def source_check(label):
        check.phase = label + "-shell-source-admission"
        C.conventional_host(D)
        D.need(all(directory_identity(Path(path)) == identity for path, identity in identities.items()),
               "Original shell task root changed")
        D.need(all(shell_directory_identity(path) == identity for path, identity in cleanup_parents.items()),
               "Original shell source/cleanup ancestry changed")
        C.no_cargo_configuration((work, root, *root.parents, temporary, *temporary.parents,
                                  source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                                  work / "cargo", work / "home"))
        for name in ("config", "config.toml"):
            D.need(not (work / "cargo" / name).exists() and not (work / "cargo" / name).is_symlink(),
                   "Unexpected private shell Cargo configuration")
        for path in (source / "desktop/.npmrc", source / ".npmrc", work / "home/.npmrc"):
            D.need(not path.exists() and not path.is_symlink(), "Unexpected shell npm project configuration")
        for relative in SHELL_GENERATED:
            path = source / relative
            if relative in generated:
                value = path.lstat()
                D.directory(path)
                D.need(shell_directory_identity(path) == generated[relative],
                       "Original generated shell directory changed")
            else:
                D.need(not path.exists() and not path.is_symlink(), "Preexisting/unowned shell compiler output")
        head = check.command(label + "-head", [git, "rev-parse", "HEAD"], environment, source, timeout=15)
        status = check.command(label + "-status", [git, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored"],
                               environment, source, timeout=15)
        D.need(head.stdout == sha.encode("ascii") + b"\n" and head.stderr == status.stderr == b"",
               "Original shell source commit/capture changed")
        shell_source_status(status.stdout, generated)
        if source_inputs is not None:
            D.need(shell_source_manifest(source) == source_inputs, "Original shell/frontend source anchors changed")
        if permissions is not None:
            D.need(shell_permissions_tree(source / SHELL_PERMISSIONS) == permissions,
                   "Original generated command permissions changed")

    def own_generated(relative):
        D.need(relative in SHELL_GENERATED and relative not in generated, "Different/repeated shell generated root")
        path = source / relative
        D.directory(path)
        value = path.lstat()
        D.need(value.st_uid == os.getuid() and not value.st_mode & 0o7022, "Generated shell root owner/mode differs")
        generated[relative] = shell_directory_identity(path)

    try:
        D.need(all(value is not None and Path(value).is_absolute() for value in (git, rustup, node)),
               "Selected shell compiler/frontend/source tools missing")
        source_check("before")
        source_inputs = shell_source_manifest(source)
        tree_result = check.command("source-tree", [git, "rev-parse", "HEAD^{tree}"], environment, source, timeout=15)
        tree = tree_result.stdout.strip().decode("ascii")
        D.need(tree_result.stderr == b"" and re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "Shell source tree differs")
        entry_sha = D.sha(os.environ.get("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256"))
        D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py", 1 << 20)["sha256"] == entry_sha,
               "Workflow reviewed shell lifecycle entry differs")
        local("ubuntu_publication_lifecycle").check_source_pins(source)
        source_record = {"sourceSha": sha, "sourceTree": tree, "sourceInputs": source_inputs,
                         "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                         "workflow": D.file_record(source / WORKFLOW, 128 << 10), "features": SHELL_FEATURES,
                         "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
                         "kernel": {key: getattr(os.uname(), key) for key in ("sysname", "machine", "release", "version")},
                         "lifecycleEntrySha256": entry_sha, "originalDeadline": repr(deadline),
                         "nativeQualification": False, "scope": "Fresh normal shell and distinct observer compile only; no new package."}
        D.write(public / "source.json", D.canonical(source_record))
        check.phase = "original-shell-a-data"
        prepared = package_inputs(source, work, fixtures=False)
        D.write(public / "runtime-inputs.json", D.canonical({"admission": C.CONVENTIONAL_SMOKE_INPUTS,
                "runtimeFiles": len(prepared[4]), "supplierRebuilt": False, "fixtureMaterialized": False}))
        for name in ("npmrc-user", "npmrc-global"):
            D.write(work / name, b"")
        (work / "npm-cache").mkdir(mode=0o700)
        npm_cache_identity = directory_identity(work / "npm-cache")
        check.command("rust-acquire", [rustup, "toolchain", "install", C.RUST, "--profile", "minimal", "--no-self-update"],
                      environment, work)
        selected = {}
        for name in ("cargo", "rustc"):
            result = check.command(name + "-selection", [rustup, "which", "--toolchain", C.RUST, name],
                                   environment, work, timeout=15)
            D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Original shell compiler selection differs")
            value = Path(result.stdout.decode("utf-8").rstrip("\n"))
            D.need(value.is_absolute() and value.resolve(strict=True) == value
                   and value.is_relative_to(work / "rustup/toolchains") and value.is_file(),
                   "Selected shell private compiler differs")
            selected[name] = str(value)
        cargo, rustc = selected["cargo"], selected["rustc"]
        version = check.command("rust-version", [rustc, "-vV"], environment, work, timeout=15)
        D.need(version.stderr == b"" and f"release: {C.RUST}\n".encode() in version.stdout
               and f"host: {TARGET}\n".encode() in version.stdout
               and b"commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\n" in version.stdout,
               "Selected shell Rust version/commit/target differs")
        environment.update(RUSTC=rustc, PATH=str(Path(cargo).parent) + os.pathsep + environment["PATH"], GITHUB_SHA=sha,
                           MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                           MRK_BUNDLED_PROTOCOL_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"])
        metadata_raw = check.command("shell-locked-inputs", [cargo, "metadata", "--locked", "--format-version", "1",
            "--no-default-features", "--features", SHELL_FEATURE_ARG, "--filter-platform", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], environment, work,
            limit=SHELL_METADATA_LIMIT).stdout
        compiler_inputs, packages_by_id = shell_compiler_inputs(source, work, cargo, rustc, metadata_raw)
        _, _, nodes_by_id = shell_cargo_metadata(metadata_raw, source, work / "target")
        observed_node = check.command("node-version", [node, "--version"], environment, work, timeout=15)
        D.need(observed_node.stdout == C.NODE.encode("ascii") + b"\n" and observed_node.stderr == b"",
               "Selected shell Node version differs")
        node = str(Path(node).resolve(strict=True))
        npm = Path(node).parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
        node_inputs = [{**D.file_record(path, MAX_BINARY), "path": str(path)} for path in (Path(node), npm)]
        check.command("npm-locked-no-scripts", [node, "--max-old-space-size=768", str(npm), "ci", "--ignore-scripts",
            "--no-audit", "--no-fund", "--userconfig", str(work / "npmrc-user"), "--globalconfig", str(work / "npmrc-global"),
            "--cache", str(work / "npm-cache"), "--registry", "https://registry.npmjs.org/"],
            environment, source / "desktop", timeout=300)
        own_generated("desktop/node_modules")
        npm_tree = shell_generated_tree(source / "desktop/node_modules", links=True)
        source_check("acquired")
        desktop = source / "desktop"
        check.command("typescript-no-emit", [node, "--max-old-space-size=768", "node_modules/typescript/bin/tsc", "--noEmit", "-p", "tsconfig.json"],
                      environment, desktop, timeout=60)
        native, native_bindings = shell_native_inputs(check, work, environment)
        check.command("vite-assets", [node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build", "--config",
                      str(desktop / "vite.config.mjs"), "--configLoader", "native", "--outDir", str(desktop / "dist")],
                      environment, desktop, timeout=90)
        own_generated("desktop/dist")
        frontend = shell_generated_tree(desktop / "dist")
        D.need(1 <= len(frontend["files"]) <= 64 and not frontend["links"]
               and any(row["path"] == "index.html" for row in frontend["files"]), "Embedded frontend output roster differs")
        frontend_record = {"node": C.NODE, "compilerTools": node_inputs, "sourceInputs": source_inputs,
                           "npmTreeSha256": npm_tree["treeSha256"], "npmFiles": len(npm_tree["files"]),
                           "dist": frontend, "embeddedBy": "tauri/custom-protocol", "devServer": False}
        frontend_pin = D.write(public / "frontend.json", D.canonical(frontend_record))
        raw = check.command("shell-compile", shell_compile_argv(cargo, source, work / "target"),
                            environment, work, timeout=900, limit=SHELL_COMPILE_LIMIT).stdout
        selections, units = shell_compiled_artifacts(raw, source, work / "target")
        shell_compiler_units(units, packages_by_id, nodes_by_id)
        root_id = next(key for key, value in packages_by_id.items()
                       if value["manifest_path"] == str(source / "desktop/src-tauri/Cargo.toml"))
        D.need(all(row["packageId"] == root_id for row in selections.values()), "Shell output package ID differs from source metadata")
        own_generated("desktop/src-tauri/gen")
        own_generated(SHELL_PERMISSIONS)
        permissions = shell_permissions_tree(source / SHELL_PERMISSIONS)
        originals, exports = {}, {}
        for role, selection in selections.items():
            destination = public / SHELL_EXPORTS[role]
            originals[role] = artifact_record(Path(selection["path"]), copy_to=destination)
            exports[role] = artifact_record(destination)
            D.need(originals[role]["identity"][:2] != exports[role]["identity"][:2]
                   and all(originals[role][key] == exports[role][key] for key in ("size", "sha256")),
                   "Shell original/fresh export differ or alias")
        native = finish_shell_native_inputs(native, {role: Path(row["path"]) for role, row in exports.items()}, native_bindings)
        native["hostBindingsRecord"] = D.write(public / "shell-host-bindings.json", D.canonical(native_bindings))
        native.update(shell_runtime_graph(prepared[3], prepared[4], native["sharedObjects"]))
        native_pin = D.write(public / "shell-native.json", D.canonical(native))
        source_check("compiled")
        D.need(shell_generated_tree(desktop / "node_modules", links=True) == npm_tree
               and shell_generated_tree(desktop / "dist") == frontend
               and directory_identity(work / "npm-cache") == npm_cache_identity,
               "Original shell frontend inputs/embedded assets changed during compilation")
        for row in [*compiler_inputs["files"], *node_inputs]:
            D.bound(Path(row["path"]), row)
        for role in SHELL_EXPORTS:
            D.need(D.same(artifact_record(Path(originals[role]["path"])), originals[role])
                   and D.same(artifact_record(Path(exports[role]["path"])), exports[role]), "Original shell output/export changed")
        compiler = {"sourceSha": sha, "sourceTree": tree, "sourceInputs": source_inputs, "features": SHELL_FEATURES,
                    "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                    "source": str(source), "target": str(work / "target"), "cargo": cargo,
                    "manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                    "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"],
                    "compilerInputs": compiler_inputs, "nativeInputs": native,
                    "nativeRecord": native_pin, "frontendRecord": frontend_pin,
                    "originalArtifacts": originals, "exportedArtifacts": exports, "selections": selections,
                    "compilerUnits": units, "generatedRoots": list(SHELL_GENERATED), "generatedPermissions": permissions}
        D.write(public / "compiler.json", D.canonical(compiler))
        source_check("after")
        check.phase = "shell-generated-cleanup"
        D.need(not check.failed and check.commands and all(row["ordinaryOwnerReturned"] is True for row in check.commands),
               "Compiler owners have not all returned before cleanup")
        inventories = {"desktop/node_modules": npm_tree, "desktop/dist": frontend,
                       "desktop/src-tauri/gen": shell_generated_tree(source / "desktop/src-tauri/gen"),
                       SHELL_PERMISSIONS: permissions}
        # Validate every deletion root before the first deletion, including the
        # whole permissions parent rather than silently ignoring sibling inputs.
        for relative, expected_tree in inventories.items():
            actual = (shell_permissions_tree(source / relative) if relative == SHELL_PERMISSIONS else
                      shell_generated_tree(source / relative, links=relative == "desktop/node_modules"))
            D.need(actual == expected_tree and shell_directory_identity(source / relative) == generated[relative],
                   "Original generated shell inventory changed before cleanup")
        for relative in SHELL_GENERATED:
            shell_remove_owned_directory(source / relative, generated[relative], cleanup_parents, deadline)
            del generated[relative]
        permissions = None
        # This live clean check still has its original private Git environment.
        source_check("clean")
        clean_tree = check.command("clean-tree", [git, "rev-parse", "HEAD^{tree}"], environment, source, timeout=15)
        D.need(clean_tree.stdout == tree.encode("ascii") + b"\n" and clean_tree.stderr == b"",
               "Original shell source tree changed during cleanup")
        check.phase = "shell-work-cleanup"
        shell_remove_owned_directory(work, identities[str(work)], cleanup_parents, deadline)
        del identities[str(work)]
        D.need(all(directory_identity(Path(path)) == identity for path, identity in identities.items())
               and all(shell_directory_identity(path) == identity for path, identity in cleanup_parents.items())
               and shell_source_manifest(source) == source_inputs,
               "Original surviving shell source/public bindings changed after cleanup")
        for path in (work, *(source / relative for relative in SHELL_GENERATED)):
            D.need(not path.exists() and not path.is_symlink(), "Compiler output remains after original cleanup")
        D.write(public / "result.json", D.canonical({"sourceSha": sha, "sourceTree": tree,
            "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "features": SHELL_FEATURES, "compilations": ["normal", "observer"], "cargoBuilds": 1,
            "frontendBuilds": 1, "shellExecuted": False, "observerExecuted": False, "supplierRebuilt": False,
            "packageBuilt": False, "helper11Rerun": False, "commands": check.commands, "qualified": False,
            "compilerCleanup": SHELL_CLEANUP_SUCCESS,
            "scope": "installed-shell-production-compiler-and-separate-harness-free-observer-only"}))
        files = [{**D.file_record(path, MAX_BINARY), "path": path.name} for path in sorted(public.iterdir())]
        retained = {row["path"]: row for row in files}
        D.need(all(all(retained[SHELL_EXPORTS[role]][key] == exports[role][key] for key in ("size", "sha256"))
                   for role in SHELL_EXPORTS), "Original shell exports changed during compiler cleanup")
        D.need(len(files) <= 1536 and sum(row["size"] for row in files) <= 1536 << 20 and time.monotonic() < deadline,
               "Original shell artifact roster/endpoint bound")
        pin = D.write(public / "shell-roster.json", D.canonical({"sourceSha": sha, "sourceTree": tree,
            "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "files": files}))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("shell_roster_sha256=" + pin["sha256"] + "\nshell_producer_attempt=" + os.environ["GITHUB_RUN_ATTEMPT"] + "\n")
        D.need(time.monotonic() < deadline, "Original shell compiler closed late")
        print("Both fresh shell outputs and embedded frontend retained; no shell, observer or installed runtime executed.", flush=True)
    except BaseException as error:
        retain_failure(root, check.phase, check.commands, error)
        raise


def verify(*, installed_compile=False):
    D.need("MRK_INSTALLED_SHELL_CASE" not in os.environ, "Shell route cannot enter publisher/headless compilation")
    D.need(os.environ.get("MRK_INSTALLED_CASE") == ("compile" if installed_compile else None),
           "Fixed compiler route differs")
    sha, source, temporary, root, deadline = resumed_preparation()
    os.umask(0o077)
    work, public = root / "work", root / "public"
    original_root, original_work = directory_identity(root), directory_identity(work)
    original_public, original_cases = directory_identity(public), directory_identity(root / "cases")
    # Only the accepted ordinary owner is imported nonroot. The root boundary
    # has a separately pinned protected closure and never imports this driver.
    sys.path.insert(0, str(source / "src"))
    from mobile_release.owned_process import run_owned
    check = Check(root, run_owned, deadline=deadline)
    environment = C.clean_environment(work)
    git, rustup = shutil.which("git", path=environment["PATH"]), shutil.which("rustup", path=environment["PATH"])

    def source_check(label):
        check.phase = label + "-source-admission"
        C.conventional_host(D)
        D.need(directory_identity(root) == original_root and directory_identity(work) == original_work
               and directory_identity(public) == original_public and directory_identity(root / "cases") == original_cases,
               "Task root changed")
        C.no_cargo_configuration((work, root, *root.parents, temporary, *temporary.parents,
                                  source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                                  work / "cargo", work / "home"))
        D.need(all(not (work / "cargo" / name).exists() and not (work / "cargo" / name).is_symlink()
                   for name in ("config", "config.toml")), "Unexpected private Cargo configuration")
        head = check.command(label + "-head", [git, "rev-parse", "HEAD"], environment, source, timeout=15)
        D.need(head.stderr == b"" and head.stdout == sha.encode("ascii") + b"\n",
               "Publisher source commit changed")
        status = check.command(label + "-status", [git, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                               environment, source, timeout=15)
        D.need(status.stdout == status.stderr == b"", "Publisher source has modified, untracked or ignored additions")

    try:
        D.need(all(value is not None and Path(value).is_absolute() for value in (git, rustup)), "Hosted compiler/source tools missing")
        source_check("before")
        tree = check.command("source-tree", [git, "rev-parse", "HEAD^{tree}"], environment, source, timeout=15).stdout.strip().decode("ascii")
        D.need(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "Invalid source tree")
        check.phase = "reviewed-lifecycle-entry"
        entry_sha = D.sha(os.environ.get("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256"))
        D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py", 1 << 20)["sha256"] == entry_sha,
               "Workflow reviewed lifecycle entry differs")
        local("ubuntu_publication_lifecycle").check_source_pins(source)
        kernel = os.uname()
        metadata = {"sourceSha": sha, "sourceTree": tree, "workflow": D.file_record(source / WORKFLOW, 64 << 10),
                    "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                    "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
                    "kernel": {key: getattr(kernel, key) for key in ("sysname", "machine", "release", "version")},
                    "nativeQualification": False, "features": [] if installed_compile else FEATURES, "rust": C.RUST,
                    "lifecycleEntrySha256": entry_sha, "originalDeadline": repr(deadline),
                    "fixtureScope": ("Fresh feature-off installed candidate compile only; no execution or package build."
                                     if installed_compile else "P0/F1 nonrelease packages and an unlaunched std-only app fixture; no real desktop build.")}
        D.write(public / "source.json", D.canonical(metadata))
        check.phase = "original-a-data"
        prepared = package_inputs(source, work, fixtures=not installed_compile)
        D.write(public / "runtime-inputs.json", D.canonical({"admission": C.CONVENTIONAL_SMOKE_INPUTS,
                "runtimeFiles": 607, "fixtureManifestSha256": F1_MANIFEST_SHA256,
                "fixtureChange": ("F1 anchor checked as DATA; no F1 copy or package materialized in this compile-only job."
                    if installed_compile else "Exactly one LF appended to the original 85440-byte manifest; all606 payload bodies unchanged.")}))
        # Current-job package metadata, not invented historical H evidence.
        check.phase = "kernel-package-metadata"
        D.need(re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,127}", kernel.release) is not None, "Kernel package query name differs")
        try:
            with Path("/proc/version_signature").open("rb") as signature:
                raw = signature.read(4097)
        except (FileNotFoundError, PermissionError) as error:
            D.write(public / "version-signature-unavailable.json", D.canonical({"reason": type(error).__name__}))
        else:
            D.need(0 < len(raw) <= 4096, "Version signature metadata bound")
            D.write(public / "version-signature.txt", raw)
        check.command("kernel-packages", ["/usr/bin/dpkg-query", "-W",
            "-f=${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
            "linux-image-" + kernel.release, "linux-image-unsigned-" + kernel.release, "linux-modules-" + kernel.release],
            environment, work, timeout=15, codes=(0, 1), limit=64 << 10)

        check.command("rust-acquire", [rustup, "toolchain", "install", C.RUST, "--profile", "minimal", "--no-self-update"], environment, work)
        selected = {}
        for name in ("cargo", "rustc"):
            result = check.command(name + "-selection", [rustup, "which", "--toolchain", C.RUST, name], environment, work, timeout=15)
            D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1, "Original compiler selection capture differs")
            selected[name] = result.stdout.decode("utf-8").rstrip("\n")
            path = Path(selected[name])
            D.need(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
                   and path.is_relative_to(work / "rustup/toolchains"), "Selected private compiler missing/different")
        cargo, rustc = selected["cargo"], selected["rustc"]
        result = check.command("rust-version", [rustc, "-vV"], environment, work, timeout=15)
        version = result.stdout.decode("ascii")
        D.need(result.stderr == b"" and f"release: {C.RUST}\n" in version and f"host: {TARGET}\n" in version
               and "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\n" in version,
               "Selected compiler identity differs")
        environment.update(RUSTC=rustc, PATH=str(Path(cargo).parent) + os.pathsep + environment["PATH"])
        metadata_raw = check.command("locked-inputs", [cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
            *([] if installed_compile else ["--features", FEATURES[0]]), "--filter-platform", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], environment, work).stdout
        source_check("acquired")
        check.phase = "native-input-provenance"
        native = native_inputs(check, source, work, environment, cargo, rustc, metadata_raw, candidate=installed_compile)
        environment.update(GITHUB_SHA=sha, MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                           MRK_BUNDLED_PROTOCOL_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"])
        originals, exports, export_identities = {}, {}, {}

        def export(label, path, leaf):
            destination = public / leaf
            originals[label] = artifact_record(path, copy_to=destination)
            export_identities[label] = artifact_record(destination)
            exports[label] = {key: export_identities[label][key] for key in ("path", "size", "sha256")}
            D.need(all(exports[label][key] == originals[label][key] for key in ("size", "sha256"))
                   and export_identities[label]["identity"][:2] != originals[label]["identity"][:2],
                   "Original compiler output and fresh export differ/alias")
            D.write(public / ("compiler-" + label + ".json"), D.canonical({"original": originals[label], "export": export_identities[label]}))

        def exported_unchanged():
            for label, row in export_identities.items():
                D.need(D.same(artifact_record(Path(row["path"])), row), "Fresh compiler export changed: " + label)

        if installed_compile:
            raw = check.command("candidate-compile", compile_argv(cargo, source, work / "target", library=True, candidate=True),
                                environment, work).stdout
            path = compiled_artifact(raw, source, work / "target", library=True, candidate=True)
            export("candidate", path, "candidate")
            source_check("compiled")
            native_record, _, _ = finish_native_inputs(check, work, environment, native,
                                                       {"candidate": Path(exports["candidate"]["path"])}, candidate=True)
            graph = installed_graph(prepared[3], prepared[4], native_record)
            D.write(public / "candidate-native.json", D.canonical(graph))
            D.write(public / "compiler.json", D.canonical({"sourceSha": sha, "sourceTree": tree, "features": [],
                "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                "source": str(source), "target": str(work / "target"),
                "manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"], "nativeInputs": native_record,
                "originalArtifacts": originals, "exportedArtifacts": export_identities}))
            exported_unchanged()
            D.need(D.same(artifact_record(path), originals["candidate"]), "Original candidate changed after export")
            source_check("after")
            D.write(public / "result.json", D.canonical({"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"],
                "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "compilations": ["candidate"], "features": [],
                "candidateExecuted": False, "helper11Rerun": False, "supplierRebuilt": False,
                "commands": check.commands, "qualified": False, "scope": "installed-passive-candidate-compile-only"}))
            files = [{**D.file_record(path, MAX_BINARY), "path": path.name} for path in sorted(public.iterdir())]
            D.need(len(files) <= 512 and sum(row["size"] for row in files) <= 1 << 30 and time.monotonic() < deadline,
                   "Original candidate artifact roster/endpoint bound")
            pin = D.write(public / "candidate-roster.json", D.canonical({"sourceSha": sha,
                "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "files": files}))
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                output.write("candidate_roster_sha256=" + pin["sha256"] + "\n"
                             + "candidate_producer_attempt=" + os.environ["GITHUB_RUN_ATTEMPT"] + "\n")
            D.need(time.monotonic() < deadline, "Original candidate preparation closed late")
            print("Fresh feature-off candidate compiled and retained; no candidate or installed runtime executed.", flush=True)
            return

        binary_raw = check.command("publisher-compile", compile_argv(cargo, source, work / "target", library=False), environment, work).stdout
        binary_path = compiled_artifact(binary_raw, source, work / "target", library=False)
        export("P0", binary_path, "mrk-runtime-publish")
        library_raw = check.command("libtest-compile", compile_argv(cargo, source, work / "target", library=True), environment, work).stdout
        library_path = compiled_artifact(library_raw, source, work / "target", library=True)
        export("libtest", library_path, "libtest")
        D.need(D.same(artifact_record(binary_path), originals["P0"])
               and D.same(artifact_record(library_path), originals["libtest"]), "Original P0/libtest output changed before F1")
        exported_unchanged()
        # Cargo reuses unchanged dependencies. Preserve P0 above before this
        # original F1 build can replace its release output; build.rs tracks M.
        f1_environment = {**environment, "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": F1_MANIFEST_SHA256}
        f1_raw = check.command("publisher-F1-compile", compile_argv(cargo, source, work / "target", library=False), f1_environment, work).stdout
        f1_path = compiled_artifact(f1_raw, source, work / "target", library=False)
        export("F1", f1_path, "mrk-runtime-publish-F1")
        D.need(exports["P0"]["sha256"] != exports["F1"]["sha256"], "Original F1 publisher did not acquire its distinct manifest anchor")
        fixture_source = public / "fixture.rs"
        fixture_pin = D.write(fixture_source, FIXTURE_SOURCE, 0o444)
        fixture_path = work / "fixture-app"
        check.command("fixture-compile", [rustc, "--edition=2021", "--crate-name", "mrk_lifecycle_fixture", "--crate-type", "bin",
            "--target", TARGET, "-C", "opt-level=3", "-C", "debuginfo=0", str(fixture_source), "-o", str(fixture_path)],
            environment, work, timeout=120)
        D.bound(fixture_source, fixture_pin)
        export("fixture", fixture_path, "fixture-app")
        source_check("compiled")
        exported_unchanged()
        test_env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home"),
                    "TMPDIR": str(root / "cases"), "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        result = check.command("kernel-selector", [exports["libtest"]["path"], KERNEL_SELECTOR, "--exact", "--test-threads=1"],
                               test_env, root / "cases", timeout=120, limit=2 << 20)
        exact_test_result(result.stdout, result.stderr, KERNEL_SELECTOR)
        check.phase = "native-output-closure"
        outputs = {label: Path(row["path"]) for label, row in exports.items()}
        native_record, notice_rows, depends = finish_native_inputs(check, work, environment, native, outputs)
        check.phase = "package-preparation"
        packages, capacity = prepare_packages(check, source, work, public, environment, outputs, notice_rows, depends, prepared)
        exported_unchanged()
        for label in ("libtest", "F1", "fixture"):
            D.need(D.same(artifact_record(Path(originals[label]["path"])), originals[label]), "Original retained compiler output changed")
        source_check("before-root")
        compiler_records = {"sourceSha": sha, "sourceTree": tree,
            "binaries": {label: exports[label] for label in ("P0", "F1", "fixture")}, "library": exports["libtest"],
            "originalArtifacts": originals, "exportedArtifacts": export_identities,
            "P0OriginalCapturedBeforeF1Overwrite": True, "fixtureSource": {**fixture_pin, "path": str(fixture_source)},
            "manifestSha256": C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"], "fixtureManifestSha256": F1_MANIFEST_SHA256,
            "protocolSha256": C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"], "nativeInputs": native_record, "capacity": capacity}
        D.write(public / "compiler.json", D.canonical(compiler_records))
        check.phase = "root-lifecycle-handoff"
        request = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "deadline": deadline, "runnerUid": os.getuid(), "runnerGid": os.getgid(), "source": str(source), "taskRoot": str(root),
            "library": exports["libtest"], "packages": packages, "compilerRecords": compiler_records}
        handoff_path = work / "lifecycle-handoff.json"
        handoff_bytes = D.canonical(request)
        D.need(len(handoff_bytes) <= 1 << 20, "Lifecycle handoff byte bound")
        handoff_pin = D.write(handoff_path, handoff_bytes)
        lifecycle = local("ubuntu_publication_lifecycle")
        argv = lifecycle.service_argv(handoff_path, handoff_pin["sha256"], entry_sha)
        client_env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home")}
        client_result = check.command("root-lifecycle", argv, client_env, work, timeout=1200, limit=2 << 20)
        # Only this original successful client result permits the fixed root
        # verifier to read matching start/StopPost/final records. Failure never
        # triggers a replacement wait, live-root inspection, retry or repair.
        check.phase = "root-lifecycle-original-result"
        lifecycle_result = lifecycle.verify_service_result(handoff_path, handoff_pin["sha256"], entry_sha, client_result, public)
        exported_unchanged()
        source_check("after")
        check.phase = "final-evidence"
        D.need(time.monotonic() < deadline, "Original lifecycle endpoint expired before final evidence")
        D.write(public / "result.json", D.canonical({"sourceSha": sha, "tests": [KERNEL_SELECTOR, lifecycle.ROOT_TEST, lifecycle.USER_TEST],
            "compilations": ["P0", "libtest", "F1", "fixture"], "helper11Rerun": False, "packages": packages,
            "lifecycle": lifecycle_result, "commands": check.commands, "inputsAndOutputsRetained": True,
            "qualified": False, "scope": "fixed-publisher-P0-F1-package-lifecycle-with-unlaunched-std-only-app-fixture"}))
        print("Publisher/package lifecycle checks passed; original evidence retained. No product qualification.", flush=True)
    except BaseException as error:
        # Never turn a failure into a pass or infer disposal from process exit.
        retain_failure(root, check.phase, check.commands, error)
        raise


def verify_installed():
    case = os.environ.get("MRK_INSTALLED_CASE")
    D.need(case in INSTALLED_CASES, "Only the three fixed installed jobs are accepted")
    sha, source, _, root, deadline = resumed_preparation()
    work, public = root / "work", root / "public"
    check, phase = None, "accepted-u-data"
    try:
        entry_sha = D.sha(os.environ.get("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256"))
        D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py", 1 << 20)["sha256"] == entry_sha,
               "Workflow reviewed installed lifecycle entry differs")
        local("ubuntu_publication_lifecycle").check_source_pins(source)
        library, packages, old_compiler, accepted = installed_u_inputs(work)
        candidate, compiler, graph, roster_sha, producer_attempt, candidate_artifact_id = installed_candidate(work, sha)
        D.need(elf_dependencies(D.read(Path(library["path"]), MAX_BINARY)) == old_compiler["nativeInputs"]["outputs"]["libtest"]["elf"],
               "Accepted original U platform executable closure differs")
        # Only after the actual U gate and all transported DATA bindings. This
        # owner still needs the externally admitted OS/bootstrap prerequisite.
        sys.path.insert(0, str(source / "src"))
        from mobile_release.owned_process import run_owned
        check = Check(root, run_owned, deadline=deadline)
        environment = C.clean_environment(work)
        original = {str(path): directory_identity(path) for path in (root, work, public, root / "cases")}

        def source_check(label):
            C.conventional_host(D)
            D.need(all(directory_identity(Path(path)) == item for path, item in original.items()), "Installed task root changed")
            head = check.command(label + "-head", ["/usr/bin/git", "rev-parse", "HEAD"], environment, source, timeout=15)
            status = check.command(label + "-status", ["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                                   environment, source, timeout=15)
            D.need(head.stdout == sha.encode("ascii") + b"\n" and head.stderr == status.stdout == status.stderr == b"",
                   "Installed source is not the exact original clean checkout")

        source_check("before")
        policy = installed_os_inputs(check, work, graph, compiler, old_compiler)
        D.write(public / "source.json", D.canonical({"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"],
            "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "case": case, "features": [], "acceptedU": accepted,
            "candidateRosterSha256": roster_sha, "platformLibrarySourceSha": old_compiler["sourceSha"],
            "candidateProducerAttempt": producer_attempt, "consumerAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "candidateArtifactId": candidate_artifact_id,
            "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
            "originalDeadline": repr(deadline), "qualified": False}))
        request = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "deadline": deadline, "runnerUid": os.getuid(), "runnerGid": os.getgid(), "source": str(source), "taskRoot": str(root),
            "library": library, "packages": packages, "compilerRecords": old_compiler,
            "installed": {"case": case, "candidate": candidate, "candidateCompiler": compiler,
                          "candidateRosterSha256": roster_sha, "candidateProducerAttempt": producer_attempt,
                          "candidateArtifactId": candidate_artifact_id,
                          "acceptedU": accepted, "loaderPolicy": policy}}
        raw = D.canonical(request)
        D.need(len(raw) <= 1 << 20 and time.monotonic() < deadline, "Installed handoff bound/endpoint")
        path = work / "lifecycle-handoff.json"
        pin = D.write(path, raw)
        lifecycle = local("ubuntu_publication_lifecycle")
        argv = lifecycle.service_argv(path, pin["sha256"], entry_sha)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home")}
        client = check.command("root-installed", argv, env, work, timeout=1200, limit=2 << 20)
        check.phase = "installed-original-result"
        result = lifecycle.verify_service_result(path, pin["sha256"], entry_sha, client, public)
        source_check("after")
        D.need(time.monotonic() < deadline, "Original installed result endpoint expired")
        D.write(public / "result.json", D.canonical({"sourceSha": sha, "case": case, "features": [],
            "candidateRosterSha256": roster_sha, "acceptedU": accepted, "lifecycle": result,
            "candidateProducerAttempt": producer_attempt, "consumerAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "candidateArtifactId": candidate_artifact_id,
            "commands": check.commands, "helper11Rerun": False, "supplierRebuilt": False,
            "qualified": False, "scope": "fixed-installed-passive-test-candidate-only"}))
        print("Fixed installed candidate observations retained with original finality; no product qualification.", flush=True)
    except BaseException as error:
        retain_failure(root, phase if check is None else check.phase, [] if check is None else check.commands, error)
        raise


def shell_project_draft_observation(observed, lifecycle):
    """Consume only verify_service_result's original-finality-gated DATA."""
    D.need(type(observed) is dict and observed.get("state") == "normal-shell-installed-runtime-connection-observed"
           and observed.get("productQualified") is False and observed.get("packageLifecycleQualified") is False
           and observed.get("shellPackageBuilt") is False, "Closed project/draft observation was relabelled as qualification")
    cases, combined, files = observed.get("cases"), observed.get("projectDraft"), observed.get("files")
    # The nineteen-case root cap is160 (158 exact names); its exporter adds the original client's
    # stdout/stderr, not two more root evidence slots or another capture.
    D.need(type(cases) is dict and set(cases) == set(lifecycle.SHELL_CASES)
           and type(combined) is dict and set(combined) == {"native", "fixture"}
           and type(files) is list and len(files) <= lifecycle.SHELL_PUBLIC_FILE_LIMIT + 2,
           "Closed project/draft receipt or exported original roster is missing")
    positive = cases["positive"]
    D.need(type(positive) is dict and set(positive) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "projectDraft", "candidateDocuments"}
           and positive["case"] == "positive" and type(positive["exitCode"]) is int and positive["exitCode"] == 0
           and positive["bootstrapReturned"] is True and positive["domAndGtkObserved"] is True and positive["maps"] == [],
           "Closed positive original result is incomplete")
    D.need(all(type(cases[name]) is dict and set(cases[name]) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps"}
               for name in ("normal", "quit-outstanding")), "A nonpositive case advertised a document receipt")
    negative = cases["settled-failure"]
    D.need(type(negative) is dict and set(negative) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps",
                                                     "qualified", "expectedFailureObserved", "failureHandoff"}
           and negative["case"] == "settled-failure" and type(negative["exitCode"]) is int and negative["exitCode"] == 1
           and negative["bootstrapReturned"] is True and negative["domAndGtkObserved"] is True and negative["maps"] == []
           and negative["qualified"] is False and negative["expectedFailureObserved"] is True
           and negative["failureHandoff"] == "original-quit-relay-loop-returned"
           and D.canonical(observed.get("settledFailure")) == D.canonical(negative),
           "Closed expected-negative original failure/handoff is missing or relabelled")
    receipt = lifecycle.shell_project_receipt(D.canonical(positive["projectDraft"]))
    D.need(D.canonical(combined["native"]) == D.canonical(receipt), "Closed positive native receipt correspondence differs")
    fixture = combined["fixture"]
    D.need(type(fixture) is dict and set(fixture) == {"fixture", "rootRetained", "hintUnchanged", "savedOutputsMatched",
                                                   "noUnexpectedEntries", "noPendingState", "entryCount", "sourceBytes",
                                                   "releaseMode", "config", "gitignore", "before", "after"}
           and fixture["fixture"] == "android-saved-readonly-v1"
           and all(fixture[key] is True for key in ("rootRetained", "hintUnchanged", "savedOutputsMatched", "noUnexpectedEntries", "noPendingState"))
           and type(fixture["entryCount"]) is int and fixture["entryCount"] == 7
           and type(fixture["sourceBytes"]) is int and fixture["sourceBytes"] == len(lifecycle.SHELL_PROJECT_SOURCE) + len(lifecycle.SHELL_PROJECT_VERSION)
           and type(fixture["releaseMode"]) is int and fixture["releaseMode"] == 0o755,
           "Closed positive Save fixture inventory DATA differs")
    for key, expected in (("config", lifecycle.SHELL_PROJECT_CONFIG), ("gitignore", lifecycle.SHELL_PROJECT_IGNORE)):
        pin = fixture[key]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256", "mode"}
               and type(pin["size"]) is int and pin["size"] == len(expected)
               and pin["sha256"] == hashlib.sha256(expected).hexdigest()
               and type(pin["mode"]) is int and pin["mode"] == 0o600, "Closed positive persisted-output DATA differs")
    D.need(receipt["readback"]["size"] == fixture["config"]["size"]
           and receipt["readback"]["sha256"] == fixture["config"]["sha256"],
           "Native fresh readback differs from the outer persisted configuration")
    # Both hashes must be the two original root captures already copied only
    # after StopPost/client finality. Save changes the inventory: before/after
    # have SEPARATE pins, not the former read-only fixture's shared digest.
    for phase in ("before", "after"):
        pin = fixture[phase]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"}
               and type(pin["size"]) is int and 0 < pin["size"] <= 8192
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Closed positive before/after inventory pin differs")
        name = "lifecycle-shell-positive-project-" + phase + ".json"
        matches = [row for row in files if type(row) is dict and row.get("path") == name]
        D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
               and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"]
               and matches[0]["sha256"] == pin["sha256"], "Original positive before/after export pin differs")
    D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"], "Save fixture incorrectly claims an unchanged inventory")
    _shell_candidate_documents_observation(positive, observed.get("candidateDocuments"), files, lifecycle)
    _shell_project_paths_observation(cases["project-paths"], observed.get("projectPaths"), files, lifecycle)
    _shell_workflow_apply_observation(cases["workflow-apply"], observed.get("workflowApply"), files, lifecycle)
    _shell_session_inputs_observation(cases, observed.get("sessionInputs"), files, lifecycle)
    _shell_metadata_save_observation(cases["metadata-save"], observed.get("metadataSave"), files, lifecycle)
    _shell_tools_offline_observation(cases, observed.get("toolsOffline"), files, lifecycle)
    return {"native": receipt, "fixture": fixture}


def shell_handoff_bytes(request, deadline):
    """Keep the original transport cap and endpoint as distinct refusals."""
    raw = D.canonical(request)
    D.need(len(raw) <= 1 << 20, "Shell handoff exceeds original byte bound (bytes=" + str(len(raw)) + ", limit=1048576)")
    D.need(time.monotonic() < deadline, "Original shell handoff endpoint expired")
    return raw


def _shell_candidate_documents_observation(positive, combined, files, lifecycle):
    """The companion receipt/fixture is mandatory, never standalone success."""
    D.need(type(combined) is dict and set(combined) == {"native", "fixture"}, "Closed candidate documents observation is missing")
    receipt = lifecycle.shell_candidate_receipt(D.canonical(positive["candidateDocuments"]))
    D.need(D.canonical(combined["native"]) == D.canonical(receipt), "Closed candidate native receipt correspondence differs")
    fixture = combined["fixture"]
    D.need(type(fixture) is dict and set(fixture) == {"fixture", "rootRetained", "documentsUnchanged", "noUnexpectedEntries",
                                                   "artifactTargetsAbsent", "entryCount", "documentBytes", "directoryMode", "fileMode",
                                                   "documents", "before", "after"}
           and fixture["fixture"] == "android-candidate-documents-v1"
           and all(fixture[key] is True for key in ("rootRetained", "documentsUnchanged", "noUnexpectedEntries", "artifactTargetsAbsent"))
           and type(fixture["entryCount"]) is int and fixture["entryCount"] == 5
           and type(fixture["documentBytes"]) is int and fixture["documentBytes"] == sum(len(raw) for raw in lifecycle.SHELL_CANDIDATE_DOCUMENTS.values())
           and type(fixture["directoryMode"]) is int and fixture["directoryMode"] == 0o700
           and type(fixture["fileMode"]) is int and fixture["fileMode"] == 0o600,
           "Closed candidate five-node unchanged inventory DATA differs")
    expected = [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in lifecycle.SHELL_CANDIDATE_DOCUMENTS.items()]
    D.need(D.canonical(fixture["documents"]) == D.canonical(expected)
           and receipt["scope"]["documents"] == len(expected), "Closed candidate document bytes or native correspondence differ")
    # These pins bind the separate before/after exports copied only after the
    # original service gate. Unlike Save, every candidate node must be unchanged.
    for phase in ("before", "after"):
        pin = fixture[phase]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"}
               and type(pin["size"]) is int and 0 < pin["size"] <= 8192
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Closed candidate before/after inventory pin differs")
        name = "lifecycle-shell-positive-candidate-" + phase + ".json"
        matches = [row for row in files if type(row) is dict and row.get("path") == name]
        D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
               and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"]
               and matches[0]["sha256"] == pin["sha256"], "Original candidate before/after export pin differs")
    D.need(fixture["before"] == fixture["after"], "Candidate documents incorrectly claim a changed inventory")



def _shell_project_paths_observation(case, combined, files, lifecycle):
    """The separately completed path case cannot replace Save/candidate proof."""
    D.need(type(case) is dict and set(case) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "projectPaths"}
           and case["case"] == "project-paths" and type(case["exitCode"]) is int and case["exitCode"] == 0
           and case["bootstrapReturned"] is True and case["domAndGtkObserved"] is True and case["maps"] == [],
           "Closed project-path original result is incomplete")
    D.need(type(combined) is dict and set(combined) == {"native", "fixture"}, "Closed project-path observation is missing")
    receipt = lifecycle.shell_path_receipt(D.canonical(case["projectPaths"]))
    D.need(D.canonical(combined["native"]) == D.canonical(receipt), "Closed project-path native receipt correspondence differs")
    fixture = combined["fixture"]
    expected = {"fixture": "project-paths-v1", "rootRetained": True, "originalsRetained": True, "noUnexpectedEntries": True,
                "noPendingState": True, "inertBytesUnchanged": True, "beforeCount": 14, "afterCount": 15, "fileCount": 5, "fileBytes": 130,
                "mutations": ["symlink", "directory-for-file", "file-for-directory", "root-mode"], "rootModes": [0o700, 0o500]}
    D.need(type(fixture) is dict and set(fixture) == set(expected) | {"before", "after"}
           and D.canonical({key: fixture[key] for key in expected}) == D.canonical(expected),
           "Closed project-path fourteen/fifteen-node fixture correspondence differs")
    for phase in ("before", "after"):
        pin = fixture[phase]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int and 0 < pin["size"] <= 8192
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Closed project-path original inventory pin differs")
        matches = [row for row in files if type(row) is dict and row.get("path") == "lifecycle-shell-project-paths-" + phase + ".json"]
        D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
               and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"] and matches[0]["sha256"] == pin["sha256"],
               "Original project-path before/after export pin differs")
    D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"], "Project-path inventory incorrectly claims unchanged fixture state")


def _shell_workflow_apply_observation(case, combined, files, lifecycle):
    """Require the fifth original plus its exact post-exit three-create inventory."""
    D.need(type(case) is dict and set(case) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "workflowApply"}
           and case["case"] == "workflow-apply" and type(case["exitCode"]) is int and case["exitCode"] == 0
           and case["bootstrapReturned"] is True and case["domAndGtkObserved"] is True and case["maps"] == [],
           "Closed workflow original result is incomplete")
    D.need(type(combined) is dict and set(combined) == {"native", "fixture"}, "Closed workflow Apply observation is missing")
    receipt = lifecycle.shell_workflow_receipt(D.canonical(case["workflowApply"]))
    D.need(D.canonical(combined["native"]) == D.canonical(receipt), "Closed workflow native receipt correspondence differs")
    fixture = combined["fixture"]
    expected = {"fixture": "android-workflow-apply-v1", "rootRetained": True, "originalsRetained": True, "createdCount": 3,
                "beforeCount": 9, "afterCount": 12, "configurationAbsent": True, "noUnexpectedEntries": True, "noPendingState": True,
                "callers": [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o640 if index == 0 else 0o600}
                            for index, (name, raw) in enumerate(lifecycle.SHELL_WORKFLOW_CALLERS.items())]}
    D.need(type(fixture) is dict and set(fixture) == set(expected) | {"before", "after"}
           and D.canonical({key: fixture[key] for key in expected}) == D.canonical(expected),
           "Closed workflow fixture originals or exact caller bytes differ")
    for phase in ("before", "after"):
        pin = fixture[phase]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int and 0 < pin["size"] <= 8192
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Closed workflow original inventory pin differs")
        matches = [row for row in files if type(row) is dict and row.get("path") == "lifecycle-shell-workflow-apply-" + phase + ".json"]
        D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
               and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"] and matches[0]["sha256"] == pin["sha256"],
               "Original workflow before/after export pin differs")
    D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"], "Workflow inventory incorrectly claims no created callers")


def _shell_session_inputs_observation(cases, combined, files, lifecycle):
    """Original native receipts and exact private fixture export pins agree.

    The four admitted session observers cannot relabel the unchanged ordinary
    twelve-method cases, qualify persistence or activate the normal product.
    """
    D.need(type(combined) is dict and set(combined) == set(lifecycle.SHELL_SESSION_CASES),
           "Closed four-case session observation is missing")
    for name in lifecycle.SHELL_SESSION_CASES:
        case, pair = cases[name], combined[name]
        D.need(type(case) is dict and set(case) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "sessionInputs"}
               and case["case"] == name and type(case["exitCode"]) is int and case["exitCode"] == 0
               and case["bootstrapReturned"] is True and case["domAndGtkObserved"] is True,
               "Closed session original result is incomplete")
        D.need(type(pair) is dict and set(pair) == {"native", "fixture"}, "Closed session receipt or fixture is missing")
        receipt = lifecycle.shell_session_receipt(D.canonical(case["sessionInputs"]), name)
        D.need(D.canonical(pair["native"]) == D.canonical(receipt), "Closed session native receipt correspondence differs")
        # The root's closed-result gate already replays every map against its
        # independently admitted loader identities. Preserve those originals,
        # not just a receipt count; this is DATA validation, not readmission.
        maps = case["maps"]
        D.need(type(maps) is list and 1 <= len(maps) <= lifecycle.SHELL_SESSION_R1_LIMIT
               and len(maps) == receipt["behavior"]["assessments"], "Closed session original R1 map count differs")
        for rows in maps:
            D.need(type(rows) is list and len(rows) == 6 and all(type(row) is dict for row in rows)
                   and [row.get("role") for row in rows] == sorted(lifecycle.PRIVATE_SONAMES | {"python", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"}),
                   "Closed session original R1 map roles differ")
            for row in rows:
                D.need(set(row) == {"role", "path", "deviceMajor", "deviceMinor", "inode"}
                       and type(row["path"]) is str and row["path"].startswith("/") and len(row["path"]) <= 4096 and "\0" not in row["path"]
                       and all(type(row[key]) is int and 0 <= row[key] < 1 << 32 for key in ("deviceMajor", "deviceMinor"))
                       and type(row["inode"]) is int and 0 < row["inode"] < 1 << 64,
                       "Closed session original R1 map shape differs")
        changed = name == "session-refusals"
        expected = {"fixture": "four-kind-session-v1", "case": name, "rootRetained": True, "originalsAccounted": True,
            "projectUnchanged": True, "sourcesOutsideProject": True, "noUnexpectedEntries": True, "noPendingState": True,
            "beforeCount": 15 if changed else 9, "afterCount": 14 if changed else 9,
            "mutations": ["changed-leaf-rename"] if changed else []}
        fixture = pair["fixture"]
        D.need(type(fixture) is dict and set(fixture) == set(expected) | {"before", "after"}
               and D.canonical({key: fixture[key] for key in expected}) == D.canonical(expected),
               "Closed session private fixture correspondence differs")
        for phase in ("before", "after"):
            pin = fixture[phase]
            D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int
                   and 0 < pin["size"] <= lifecycle.SHELL_SESSION_INVENTORY_LIMIT
                   and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
                   "Closed session original inventory pin differs")
            matches = [row for row in files if type(row) is dict and row.get("path") == "lifecycle-shell-" + name + "-" + phase + ".json"]
            D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
                   and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"] and matches[0]["sha256"] == pin["sha256"],
                   "Original session before/after export pin differs")
        D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"] if changed else fixture["before"] == fixture["after"],
               "Closed session inventory changed outside its fixed mutation")


def _shell_metadata_save_observation(case, combined, files, lifecycle):
    """Require the metadata original, both real Reviews and the exact saved locale."""
    D.need(type(case) is dict and set(case) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "metadataSave"}
           and case["case"] == "metadata-save" and type(case["exitCode"]) is int and case["exitCode"] == 0
           and case["bootstrapReturned"] is True and case["domAndGtkObserved"] is True and case["maps"] == [],
           "Closed metadata original result is incomplete")
    D.need(type(combined) is dict and set(combined) == {"native", "fixture"}, "Closed metadata Save observation is missing")
    receipt = lifecycle.shell_metadata_receipt(D.canonical(case["metadataSave"]))
    D.need(D.canonical(combined["native"]) == D.canonical(receipt), "Closed metadata native receipt correspondence differs")
    fixture = combined["fixture"]
    expected = {"fixture": "android-metadata-save-v1", "rootRetained": True, "preservedOriginals": True,
                "createdCount": 1, "replacedCount": 1, "beforeCount": 13, "afterCount": 14,
                "configurationUnchanged": True, "noUnexpectedEntries": True, "noPendingState": True,
                "files": [{"path": lifecycle.SHELL_METADATA_LOCALE + "/" + name, "size": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o600}
                          for name, raw in (("title.txt", lifecycle.SHELL_METADATA_TITLE),
                                            ("short_description.txt", lifecycle.SHELL_METADATA_SHORT_AFTER),
                                            ("keep.txt", lifecycle.SHELL_METADATA_KEEP),
                                            ("full_description.txt", lifecycle.SHELL_METADATA_FULL))]}
    D.need(type(fixture) is dict and set(fixture) == set(expected) | {"before", "after"}
           and D.canonical({key: fixture[key] for key in expected}) == D.canonical(expected),
           "Closed metadata fixture originals or exact saved bytes differ")
    for phase in ("before", "after"):
        pin = fixture[phase]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int and 0 < pin["size"] <= 8192
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Closed metadata original inventory pin differs")
        matches = [row for row in files if type(row) is dict and row.get("path") == "lifecycle-shell-metadata-save-" + phase + ".json"]
        D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
               and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"] and matches[0]["sha256"] == pin["sha256"],
               "Original metadata before/after export pin differs")
    D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"], "Metadata inventory incorrectly claims no saved text")


def shell_tools_input_root():
    """Only the fixed disposable job; this DATA helper owns no process runner."""
    D.need(os.environ.get("GITHUB_REF") == SHELL_REF and os.environ.get("GITHUB_ACTIONS") == "true"
           and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.geteuid() != 0,
           "Tools input preparation is restricted to the nonroot disposable hosted job")
    C.conventional_host(D)
    run, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    D.need(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (run, attempt)), "Tools input original run identity differs")
    parent = Path(os.environ.get("RUNNER_TEMP", ""))
    D.need(parent.is_absolute() and ".." not in parent.parts, "Tools input original parent differs")
    root = parent / ("mrk-desktop-tools-" + run + "-" + attempt)
    directory_identity(root)
    return root


def shell_tools_input_nodes():
    """Bound literal public metadata/bytes only; never follow an unknown alias."""
    nodes, originals = {}, []
    for name in (*SHELL_TOOLS_DIRECTORIES, *SHELL_TOOLS_PROGRAMS, *SHELL_TOOLS_LINKS):
        path = Path(name)
        if name != "/" and nodes.get(str(path.parent), {}).get("kind") != "directory":
            nodes[name] = {"kind": "parent-unavailable"}
            continue
        try:
            before = path.lstat()
        except FileNotFoundError:
            nodes[name] = {"kind": "absent"}
            originals.append((path, None))
            continue
        original = [before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
                    before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns]
        row = {"kind": "refused", "identity": original}
        protected = before.st_uid == before.st_gid == 0 and before.st_mode & 0o022 == 0
        if name in SHELL_TOOLS_DIRECTORIES and protected and stat.S_ISDIR(before.st_mode) and before.st_mode & 0o005 == 0o005:
            row["kind"] = "directory"
        elif name in SHELL_TOOLS_PROGRAMS and protected and stat.S_ISREG(before.st_mode) and before.st_nlink == 1 \
                and before.st_mode & 0o6000 == 0 and before.st_mode & 0o111 == 0o111 and 0 < before.st_size <= 16 << 20:
            row.update(kind="file", **D.file_record(path, 16 << 20))
        elif name in SHELL_TOOLS_LINKS and before.st_uid == before.st_gid == 0 and stat.S_ISLNK(before.st_mode) \
                and before.st_nlink == 1 and 0 < before.st_size <= 4096:
            target = os.readlink(path)
            D.need(target.isascii() and all(32 <= ord(char) < 127 for char in target) and len(target) == before.st_size,
                   "Tools public alias DATA exceeds its fixed shape")
            row.update(kind="symlink", target=target)
        nodes[name] = row
        originals.append((path, original))
    for path, original in originals:
        if original is None:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            D.need(False, "Absent Tools input appeared during its original snapshot")
        after = path.lstat()
        D.need(original == [after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
                           after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns], "Tools input changed during its original snapshot")
    return nodes


def shell_tools_package_data(raw):
    D.need(type(raw) is bytes and len(raw) <= 64 << 10 and raw.endswith(b"\n"), "Tools package query DATA is incomplete")
    rows = {}
    for line in raw.decode("ascii").split("\n")[:-1]:
        fields = line.split("\t")
        D.need(len(fields) == 6 and all(0 < len(field) <= 256 and all(32 <= ord(char) < 127 for char in field) for field in fields),
               "Tools package query fields differ")
        name = fields[0].removesuffix(":amd64")
        D.need(name in SHELL_TOOLS_PACKAGES and name not in rows and fields[0] in (name, name + ":amd64"),
               "Tools package query roster differs")
        rows[name] = fields
    D.need({"git", "python3.12"} <= set(rows), "Tools original Git/Python package query is missing")
    for name, fields in rows.items():
        D.need(fields[1] == "installed" and fields[3] == "amd64" and all(fields[index] for index in (2, 4, 5)),
               "Tools original package is not an installed amd64 supplier")
    return rows


def _shell_tools_input_document(raw, phase, root):
    """Closed preparation DATA, not an alternate executable-admission policy."""
    data = D.decode(raw, 64 << 10)
    D.need(type(data) is dict and set(data) == {"schema", "phase", "qualified", "sourceSha", "runId", "attempt", "rootIdentity",
                                               "originalStepExit", "nodes", "packageQuery"}
           and D.canonical(data) == raw and data["schema"] == "fixed-disposable-shell-tools-inputs-v1" and data["phase"] == phase
           and data["qualified"] is False and data["sourceSha"] == os.environ["GITHUB_SHA"]
           and data["runId"] == os.environ["GITHUB_RUN_ID"] and data["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
           and type(data["rootIdentity"]) is list and all(type(n) is int for n in data["rootIdentity"])
           and data["rootIdentity"] == list(directory_identity(root)), "Original Tools preparation identity differs")
    D.need(data["originalStepExit"] is None if phase in ("before", "namespace-before") else
           type(data["originalStepExit"]) is int and 0 <= data["originalStepExit"] <= 255,
           "Tools original preparation return is not typed DATA")
    nodes = data["nodes"]
    D.need(type(nodes) is dict and set(nodes) == set((*SHELL_TOOLS_DIRECTORIES, *SHELL_TOOLS_PROGRAMS, *SHELL_TOOLS_LINKS)),
           "Tools original public node roster differs")
    for name, row in nodes.items():
        D.need(type(row) is dict and row.get("kind") in ("absent", "parent-unavailable", "refused", "directory", "file", "symlink"),
               "Tools original node kind differs")
        kind = row["kind"]
        fields = {"kind"} if kind in ("absent", "parent-unavailable") else {"kind", "identity"}
        fields |= {"path", "size", "sha256"} if kind == "file" else {"target"} if kind == "symlink" else set()
        D.need(set(row) == fields, "Tools original node fields differ")
        if "identity" not in row:
            continue
        identity = row["identity"]
        D.need(type(identity) is list and len(identity) == 9 and all(type(n) is int and 0 <= n < 1 << 64 for n in identity)
               and identity[0] > 0 and identity[1] > 0 and identity[5] > 0, "Tools original node identity differs")
        if kind == "refused":
            continue  # Retained failure DATA can never establish a successful pair.
        D.need(identity[3:5] == [0, 0], "Tools original public supplier is not root-owned")
        if kind == "directory":
            D.need(name in SHELL_TOOLS_DIRECTORIES and stat.S_ISDIR(identity[2]) and identity[2] & 0o022 == 0
                   and identity[2] & 0o005 == 0o005, "Tools original protected directory differs")
        elif kind == "file":
            D.need(name in SHELL_TOOLS_PROGRAMS and stat.S_ISREG(identity[2]) and identity[2] & 0o6022 == 0
                   and identity[2] & 0o111 == 0o111 and identity[5] == 1 and 0 < identity[6] <= 16 << 20
                   and row["path"] == Path(name).name and type(row["size"]) is int and row["size"] == identity[6]
                   and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
                   "Tools original public executable DATA differs")
        else:
            D.need(name in SHELL_TOOLS_LINKS and stat.S_ISLNK(identity[2]) and identity[5] == 1
                   and type(row["target"]) is str and row["target"].isascii() and 0 < len(row["target"]) == identity[6] <= 4096
                   and all(32 <= ord(char) < 127 for char in row["target"]), "Tools original literal alias DATA differs")
    query = data["packageQuery"]
    D.need(type(query) is dict and set(query) == {"stdout", "stderr", "exitCode"}
           and type(query["exitCode"]) is int and 0 <= query["exitCode"] <= 255, "Tools original package query return differs")
    for key, limit in (("stdout", 64 << 10), ("stderr", 4096)):
        pin = query[key]
        D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int and 0 <= pin["size"] <= limit
               and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
               "Tools original package query pin differs")
    return data


def _shell_tools_namespace_sources():
    """Current source DATA only; never a privileged module/dispatcher import."""
    return [{**D.file_record(SOURCE / path, limit), "path": path}
            for path, limit in SHELL_TOOLS_NAMESPACE_SOURCES.items()]


def _shell_tools_namespace_query(root):
    return (D.read(root / "before-packages.tsv", 64 << 10),
            D.read(root / "before-packages.stderr", 4096), D.read(root / "before-packages.exit", 4))


def _shell_tools_namespace_identity(value):
    D.need(type(value) is list and len(value) == 9
           and all(type(n) is int and 0 <= n < 1 << 64 for n in value)
           and value[0] > 0 and value[1] > 0 and value[5] > 0, "JVM namespace original identity differs")
    return value


def shell_tools_namespace_disposition(raw, root, query):
    """Closed DATA decision only. Refused payloads are never repaired/admitted."""
    data = D.decode(raw, 64 << 10)
    D.need(type(data) is dict and set(data) == {"schema", "qualified", "source", "sourceFiles", "snapshot"}
           and D.canonical(data) == raw and data["schema"] == "fixed-disposable-shell-jvm-namespace-before-v1"
           and data["qualified"] is False and data["source"] == str(SOURCE), "JVM namespace source envelope differs")
    sources = data["sourceFiles"]
    D.need(type(sources) is list and len(sources) == len(SHELL_TOOLS_NAMESPACE_SOURCES), "JVM namespace source roster differs")
    for row, (path, limit) in zip(sources, SHELL_TOOLS_NAMESPACE_SOURCES.items()):
        D.need(type(row) is dict and set(row) == {"path", "size", "sha256"} and row["path"] == path
               and type(row["size"]) is int and 0 < row["size"] <= limit
               and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
               "JVM namespace original source pin differs")
    snapshot = _shell_tools_input_document(D.canonical(data["snapshot"]), "namespace-before", root)
    D.need(type(query) is tuple and len(query) == 3, "JVM namespace package query DATA differs")
    package_raw, stderr, exit_raw = query
    D.need(type(stderr) is bytes and len(stderr) <= 4096 and type(exit_raw) is bytes
           and re.fullmatch(rb"(?:0|[1-9][0-9]{0,2})\n", exit_raw) is not None and int(exit_raw) <= 255,
           "JVM namespace original package return differs")
    packages = shell_tools_package_data(package_raw)
    D.need(snapshot["packageQuery"] == {"stdout": {"size": len(package_raw), "sha256": hashlib.sha256(package_raw).hexdigest()},
                                      "stderr": {"size": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()},
                                      "exitCode": int(exit_raw)}, "JVM namespace original package bytes changed")
    absent = set(packages) == {"git", "python3.12"}
    D.need(absent and stderr == SHELL_TOOLS_JDK_MISSING and exit_raw == b"1\n"
           or set(packages) == set(SHELL_TOOLS_PACKAGES) and stderr == b"" and exit_raw == b"0\n",
           "JVM namespace package pair is partial, unknown or ambiguously absent")
    nodes = snapshot["nodes"]
    D.need(all(nodes[path]["kind"] == "directory" for path in SHELL_TOOLS_NAMESPACE_PARENTS)
           and all(nodes[path]["kind"] == "file" for path in SHELL_TOOLS_PROGRAMS[:2])
           and all(nodes[path]["kind"] in ("symlink", "absent") for path in SHELL_TOOLS_LINKS),
           "JVM namespace must not repair an unrelated refused input")
    original = nodes[SHELL_TOOLS_NAMESPACE_PARENT]
    if original["kind"] == "directory":
        return data, "protected"
    descendants = (SHELL_TOOLS_JDK_ROOT, SHELL_TOOLS_JDK_ROOT + "/bin", *SHELL_TOOLS_PROGRAMS[2:])
    D.need(all(nodes[path] == {"kind": "parent-unavailable"} for path in descendants),
           "Refused/absent JVM descendants are not admitted missing payloads")
    if original["kind"] == "absent":
        return data, "absent"
    D.need(original["kind"] == "refused" and original["identity"][2:5] == [stat.S_IFDIR | 0o777, 0, 0]
           and absent, "Only an original root-owned ordinary0777 JVM with a genuinely absent pair may be preserved")
    return data, "preserve-create"


def shell_tools_namespace_snapshot():
    """Preserve the actual unsafe observation before any namespace constructor."""
    root = shell_tools_input_root()
    original_root = directory_identity(root)
    raw, stderr, exit_raw = query = _shell_tools_namespace_query(root)
    D.need(re.fullmatch(rb"(?:0|[1-9][0-9]{0,2})\n", exit_raw) is not None and int(exit_raw) <= 255,
           "JVM namespace original package return is missing")
    snapshot = {"schema": "fixed-disposable-shell-tools-inputs-v1", "phase": "namespace-before", "qualified": False,
        "sourceSha": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "rootIdentity": list(original_root), "originalStepExit": None, "nodes": shell_tools_input_nodes(),
        "packageQuery": {"stdout": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                         "stderr": {"size": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}, "exitCode": int(exit_raw)}}
    document = {"schema": "fixed-disposable-shell-jvm-namespace-before-v1", "qualified": False,
                "source": str(SOURCE), "sourceFiles": _shell_tools_namespace_sources(), "snapshot": snapshot}
    body = D.canonical(document)
    D.need(len(body) <= 64 << 10, "JVM namespace original snapshot exceeds its bound")
    D.write(root / "namespace-before.json", body)  # Failure DATA is retained before the disposition assertion.
    D.need(directory_identity(root) == original_root, "JVM namespace original evidence root changed")
    _, disposition = shell_tools_namespace_disposition(body, root, query)
    print(disposition, flush=True)  # Informational only; never passed to root as effect authority.


def _shell_tools_namespace_result(root, *, before=None):
    """Require the original returned construction, never a success boolean alone."""
    contents = {name: D.read(root / name, limit) for name, limit in SHELL_TOOLS_NAMESPACE_FILES.items()}
    pins = {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in contents.items()}
    original, disposition = shell_tools_namespace_disposition(contents["namespace-before.json"], root, _shell_tools_namespace_query(root))
    snapshot = original["snapshot"]
    D.need(contents["namespace.exit"] == b"0\n" and contents["namespace.stderr"] == b"",
           "JVM namespace original constructor did not return cleanly")
    result = D.decode(contents["namespace.stdout"], 16 << 10)
    fields = {"schema", "qualified", "sourceSha", "runId", "attempt", "root", "rootIdentity", "source", "sourceFiles",
              "namespaceBefore", "disposition", "stage", "parents", "original", "preservation", "preserved", "fresh",
              "query", "actions", "originalFdsClosed", "completed", "failure"}
    D.need(type(result) is dict and set(result) == fields and D.canonical(result) == contents["namespace.stdout"]
           and result["schema"] == "fixed-disposable-shell-jvm-namespace-result-v1" and result["qualified"] is False
           and result["sourceSha"] == snapshot["sourceSha"] and result["runId"] == snapshot["runId"] and result["attempt"] == snapshot["attempt"]
           and result["root"] == str(root) and D.same(result["rootIdentity"], snapshot["rootIdentity"])
           and result["source"] == original["source"] and D.same(result["sourceFiles"], original["sourceFiles"])
           and D.same(result["sourceFiles"], _shell_tools_namespace_sources())
           and D.same(result["namespaceBefore"], pins["namespace-before.json"])
           and result["disposition"] == disposition and result["stage"] == "complete"
           and result["originalFdsClosed"] is True and result["completed"] is True and result["failure"] is None,
           "JVM namespace original source/run/root/result binding differs")
    parents = result["parents"]
    D.need(type(parents) is dict and set(parents) == set(SHELL_TOOLS_NAMESPACE_PARENTS), "JVM namespace protected parent roster differs")
    for path in SHELL_TOOLS_NAMESPACE_PARENTS:
        identity = _shell_tools_namespace_identity(parents[path])
        D.need(identity[:5] == snapshot["nodes"][path]["identity"][:5], "JVM namespace protected parent changed")
    actions = result["actions"]
    D.need(type(actions) is dict and set(actions) == {"preservationCreated", "renameReturned", "freshCreated"}
           and all(type(value) is bool for value in actions.values())
           and all(value is (disposition == "preserve-create") for value in actions.values()),
           "JVM namespace original effect returns differ")
    old_node = snapshot["nodes"][SHELL_TOOLS_NAMESPACE_PARENT]
    if disposition == "preserve-create":
        old = _shell_tools_namespace_identity(result["original"])
        preserved = _shell_tools_namespace_identity(result["preserved"])
        fresh = _shell_tools_namespace_identity(result["fresh"])
        container = result["preservation"]
        D.need(type(container) is dict and set(container) == {"path", "identity"}
               and container["path"] == "/usr/lib/mrk-desktop-jvm-original-" + snapshot["runId"] + "-" + snapshot["attempt"],
               "JVM namespace preservation path differs")
        parent = _shell_tools_namespace_identity(container["identity"])
        D.need(old == old_node["identity"] and preserved[:5] == old[:5]
               and fresh[2:5] == [stat.S_IFDIR | 0o755, 0, 0] and parent[2:5] == [stat.S_IFDIR | 0o700, 0, 0]
               and old[0] == fresh[0] == parent[0] == parents["/usr/lib"][0]
               and len({tuple(old[:2]), tuple(fresh[:2]), tuple(parent[:2])}) == 3,
               "JVM namespace must preserve the old inode and construct a distinct protected one")
        query = result["query"]
        D.need(type(query) is dict and set(query) == {"stdout", "stderr", "exitCode", "originalReturned", "stdoutEof", "stderrEof", "streamsClosed", "stopSent"}
               and query["stdout"] == "" and query["stderr"] == SHELL_TOOLS_JDK_MISSING.decode("ascii")
               and type(query["exitCode"]) is int and query["exitCode"] == 1
               and all(query[key] is True for key in ("originalReturned", "stdoutEof", "stderrEof", "streamsClosed"))
               and query["stopSent"] is False, "JVM namespace original bounded root query is not absent-pair finality")
        expected_node = {"kind": "directory", "identity": fresh}
    else:
        expected_original = old_node.get("identity")
        D.need(D.same(result["original"], expected_original)
               and all(result[key] is None for key in ("preservation", "preserved", "fresh", "query")),
               "No-op JVM namespace must not claim relocation, creation or package query")
        expected_node = old_node
    if before is None:
        nodes = shell_tools_input_nodes()
    else:
        D.need(before["phase"] == "before" and before["packageQuery"] == snapshot["packageQuery"],
               "Strict pair-before is not the original pre-installation package query")
        nodes = before["nodes"]
    actual = nodes[SHELL_TOOLS_NAMESPACE_PARENT]
    D.need(actual["kind"] == expected_node["kind"] and
           (actual == expected_node if actual["kind"] == "absent" else actual["identity"][:5] == expected_node["identity"][:5]),
           "Constructed JVM namespace is not the original strict-before namespace")
    D.need(all(nodes[path] == snapshot["nodes"][path] for path in (*SHELL_TOOLS_PROGRAMS[:2], *SHELL_TOOLS_LINKS))
           and all(nodes[path]["kind"] == "directory" and nodes[path]["identity"][:5] == snapshot["nodes"][path]["identity"][:5]
                   for path in SHELL_TOOLS_NAMESPACE_PARENTS),
           "JVM namespace construction changed an original unrelated input")
    return pins


def shell_tools_namespace_check():
    _shell_tools_namespace_result(shell_tools_input_root())


def shell_tools_input_snapshot(phase):
    """Snapshot even an actual failed preparation; no installation/launch here."""
    D.need(phase in ("before", "after"), "Different fixed Tools preparation phase")
    root = shell_tools_input_root()
    original_root = directory_identity(root)
    raw = D.read(root / (phase + "-packages.tsv"), 64 << 10)
    stderr = D.read(root / (phase + "-packages.stderr"), 4096)
    exit_raw = D.read(root / (phase + "-packages.exit"), 4)
    D.need(re.fullmatch(rb"(?:0|[1-9][0-9]{0,2})\n", exit_raw) is not None and int(exit_raw) <= 255,
           "Tools package original return DATA differs")
    step = os.environ.get("MRK_SHELL_TOOLS_PREPARATION_EXIT", "") if phase == "after" else None
    D.need(phase == "before" or re.fullmatch(r"0|[1-9][0-9]{0,2}", step) is not None and int(step) <= 255,
           "Tools original preparation return is missing")
    nodes = shell_tools_input_nodes()
    source_sha = os.environ.get("GITHUB_SHA", "")
    D.need(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "Tools original source identity differs")
    document = {"schema": "fixed-disposable-shell-tools-inputs-v1", "phase": phase, "qualified": False,
        "sourceSha": source_sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "rootIdentity": list(original_root), "originalStepExit": int(step) if step is not None else None, "nodes": nodes,
        "packageQuery": {"stdout": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                         "stderr": {"size": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()}, "exitCode": int(exit_raw)}}
    # Preserve the actual snapshot before any successful-pair assertion. A
    # missing/failed after snapshot remains failure, never cleanup evidence.
    D.write(root / (phase + ".json"), D.canonical(document))
    D.need(directory_identity(root) == original_root and int(exit_raw) in ((0, 1) if phase == "before" else (0,)),
           "Tools original directory or package query failed")
    packages = shell_tools_package_data(raw)
    D.need(all(nodes[path].get("kind") == "file" for path in SHELL_TOOLS_PROGRAMS[:2])
           and all(row["kind"] in ("directory", "file", "symlink", "absent", "parent-unavailable") for row in nodes.values()),
           "Tools preparation must not repair a refused original Git/Python/JDK path")
    if phase == "before":
        _shell_tools_namespace_result(root, before=document)
        print("present" if all(nodes[path].get("kind") == "file" for path in SHELL_TOOLS_PROGRAMS[2:]) else "absent", flush=True)
        return
    before_raw = D.read(root / "before.json", 64 << 10)
    before = _shell_tools_input_document(before_raw, "before", root)
    old_packages_raw = D.read(root / "before-packages.tsv", 64 << 10)
    D.need(before["packageQuery"]["stdout"] == {"size": len(old_packages_raw), "sha256": hashlib.sha256(old_packages_raw).hexdigest()},
           "Tools original before package bytes changed")
    old_packages = shell_tools_package_data(old_packages_raw)
    D.need(step == "0" and stderr == b"" and set(packages) == set(SHELL_TOOLS_PACKAGES)
           and all(nodes[path].get("kind") == "file" for path in SHELL_TOOLS_PROGRAMS)
           and all(nodes[path].get("kind") == "symlink" and nodes[path].get("target") == target for path, target in SHELL_TOOLS_LINKS.items())
           and all(nodes[path].get("kind") == "directory" for path in SHELL_TOOLS_DIRECTORIES),
           "Original disposable Tools preparation did not establish the fixed pair")
    D.need(all(nodes[path] == before["nodes"][path] for path in SHELL_TOOLS_PROGRAMS[:2])
           and all(packages[name] == old_packages[name] for name in ("git", "python3.12")),
           "JDK preparation changed the original Git/Python input")
    D.need(all(before["nodes"][path].get("kind") != "directory" or before["nodes"][path]["identity"][:5] == nodes[path]["identity"][:5]
               for path in SHELL_TOOLS_DIRECTORIES), "JDK preparation replaced an original protected ancestor")


def shell_tools_inputs_for_observation():
    """Rebind the actual prepared pair, Git and Python before/after native work."""
    root = shell_tools_input_root()
    snapshots, packages, pins = {}, {}, {}
    for phase in ("before", "after"):
        raw = D.read(root / (phase + ".json"), 64 << 10)
        data = _shell_tools_input_document(raw, phase, root)
        pins[phase + ".json"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for suffix, key, limit in ((".tsv", "stdout", 64 << 10), (".stderr", "stderr", 4096), (".exit", None, 4)):
            name = phase + "-packages" + suffix
            content = D.read(root / name, limit)
            pin = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            if key is not None:
                D.need(data["packageQuery"][key] == pin, "Tools original package query bytes changed")
            else:
                D.need(content == (str(data["packageQuery"]["exitCode"]) + "\n").encode("ascii"), "Tools original package query return changed")
            pins[name] = pin
            if key == "stdout":
                packages[phase] = shell_tools_package_data(content)
        snapshots[phase] = data
    before, after = snapshots["before"], snapshots["after"]
    D.need(before["originalStepExit"] is None and type(after["originalStepExit"]) is int and after["originalStepExit"] == 0
           and before["packageQuery"]["exitCode"] in (0, 1)
           and type(after["packageQuery"]["exitCode"]) is int and after["packageQuery"]["exitCode"] == 0
           and after["packageQuery"]["stderr"]["size"] == 0 and set(packages["after"]) == set(SHELL_TOOLS_PACKAGES)
           and all(packages["before"][name] == packages["after"][name] for name in ("git", "python3.12")),
           "Tools original preparation failed or changed Git/Python packages")
    current = shell_tools_input_nodes()
    D.need(set(after["nodes"]) == set(before["nodes"]) == set(current)
           and all(current[path].get("kind") == "file" and current[path] == after["nodes"][path] for path in SHELL_TOOLS_PROGRAMS)
           and all(current[path] == after["nodes"][path] and current[path].get("kind") == "symlink"
                   and current[path].get("target") == target for path, target in SHELL_TOOLS_LINKS.items())
           and all(current[path].get("kind") == "directory" and current[path]["identity"][:5] == after["nodes"][path]["identity"][:5]
                    for path in SHELL_TOOLS_DIRECTORIES)
           and all(before["nodes"][path].get("kind") != "directory" or before["nodes"][path]["identity"][:5] == current[path]["identity"][:5]
                   for path in SHELL_TOOLS_DIRECTORIES)
           and all(row["kind"] != "refused" for row in before["nodes"].values())
           and all(before["nodes"][path] == current[path] for path in SHELL_TOOLS_PROGRAMS[:2]),
           "Actual Git/Python/JDK pair drifted from the original disposable preparation")
    # Ordinary P0 publication can change directory timestamps/size. Preserve
    # those original snapshot facts, but only stable protected parent identity
    # is authority across native work; executable and alias rows remain exact.
    bound_nodes = {path: {**row, "identity": row["identity"][:5]} if row["kind"] == "directory" else row
                   for path, row in current.items()}
    pins.update(_shell_tools_namespace_result(root, before=before))
    return {"schema": after["schema"], "qualified": False, "preparationFiles": pins, "nodes": bound_nodes, "packages": packages["after"]}


def _shell_tools_offline_observation(cases, combined, files, lifecycle):
    """Eight original engineering cases, including negative/refused outcomes.

    This never activates ordinary Tools/Offline or claims the full1800s expiry.
    Native booleans alone cannot replace the retained exact fixture inventories.
    """
    D.need(type(cases) is dict and set(lifecycle.SHELL_TOOLS_OFFLINE_CASES) <= set(cases)
           and type(combined) is dict and set(combined) == set(lifecycle.SHELL_TOOLS_OFFLINE_CASES),
           "Closed eight-case Tools/Offline observation is missing")
    for name in lifecycle.SHELL_TOOLS_OFFLINE_CASES:
        case, pair = cases[name], combined[name]
        D.need(type(case) is dict and set(case) == {"case", "exitCode", "bootstrapReturned", "domAndGtkObserved", "maps", "toolsOffline"}
               and case["case"] == name and type(case["exitCode"]) is int and case["exitCode"] == 0
               and case["bootstrapReturned"] is True and case["domAndGtkObserved"] is True and case["maps"] == [],
               "Closed Tools/Offline original result is incomplete")
        D.need(type(pair) is dict and set(pair) == {"native", "fixture"}, "Closed Tools/Offline receipt or fixture is missing")
        receipt = lifecycle.shell_tools_offline_receipt(D.canonical(case["toolsOffline"]), name)
        D.need(D.canonical(pair["native"]) == D.canonical(receipt), "Closed Tools/Offline native receipt correspondence differs")
        config = lifecycle.SHELL_TOOLS_OFFLINE_CONFIGS[name]
        drift = name == "offline-drift"
        mutations = (["project/release/mobile-release.json"] if drift else
                     ["project/script.trace"] if lifecycle.SHELL_TOOLS_OFFLINE_TRACES[name] else [])
        expected = {"fixture": "installed-tools-offline-fixture-v1", "case": name, "rootRetained": True, "originalsAccounted": True,
            "noUnexpectedEntries": True, "noPendingState": True, "beforeCount": 21, "afterCount": 21, "mutations": mutations,
            "scriptTrace": lifecycle.SHELL_TOOLS_OFFLINE_TRACES[name].decode("ascii"), "laterTrace": "", "savedConfigChanged": drift,
            "savedConfigBefore": {"bytes": len(config), "sha256": hashlib.sha256(config).hexdigest()},
            "savedConfigAfter": {"bytes": len(config) + drift, "sha256": hashlib.sha256(config + (b"\n" if drift else b"")).hexdigest()}}
        fixture = pair["fixture"]
        D.need(type(fixture) is dict and set(fixture) == set(expected) | {"before", "after"}
               and D.canonical({key: fixture[key] for key in expected}) == D.canonical(expected)
               and D.canonical(receipt["fixture"]) == D.canonical({key: fixture[key]
                   for key in ("scriptTrace", "laterTrace", "savedConfigChanged")}),
               "Closed Tools/Offline synthetic fixture or same-original changes differ")
        for phase in ("before", "after"):
            pin = fixture[phase]
            D.need(type(pin) is dict and set(pin) == {"size", "sha256"} and type(pin["size"]) is int
                   and 0 < pin["size"] <= lifecycle.SHELL_TOOLS_OFFLINE_INVENTORY_LIMIT
                   and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
                   "Closed Tools/Offline original inventory pin differs")
            matches = [row for row in files if type(row) is dict and row.get("path") == "lifecycle-shell-" + name + "-" + phase + ".json"]
            D.need(len(matches) == 1 and set(matches[0]) == {"path", "size", "sha256"}
                   and type(matches[0]["size"]) is int and matches[0]["size"] == pin["size"] and matches[0]["sha256"] == pin["sha256"],
                   "Original Tools/Offline before/after export pin differs")
        D.need(fixture["before"]["sha256"] != fixture["after"]["sha256"] if mutations else fixture["before"] == fixture["after"],
               "Closed Tools/Offline inventory changed outside its fixed in-place mutation")


def verify_installed_shell():
    """One installed connection gate; reuse U, not its entire lifecycle again."""
    D.need(os.environ.get("MRK_INSTALLED_SHELL_CASE") == "observe", "Only the fixed shell observation job is accepted")
    sha, source, _, root, deadline = resumed_preparation()
    work, public = root / "work", root / "public"
    check, phase = None, "accepted-shell-data"
    try:
        entry_sha = D.sha(os.environ.get("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256"))
        D.need(D.file_record(source / "desktop/tools/ubuntu_publication_lifecycle.py", 1 << 20)["sha256"] == entry_sha,
               "Workflow reviewed shell lifecycle entry differs")
        local("ubuntu_publication_lifecycle").check_source_pins(source)
        library, packages, old_compiler, accepted = installed_u_inputs(work)
        binaries, compiler, native, roster_sha, producer_attempt, artifact_id = installed_shell_candidate(work, sha)
        D.need(elf_dependencies(D.read(Path(library["path"]), MAX_BINARY)) == old_compiler["nativeInputs"]["outputs"]["libtest"]["elf"],
               "Accepted U platform executable closure differs")
        sys.path.insert(0, str(source / "src"))
        from mobile_release.owned_process import run_owned
        check = Check(root, run_owned, deadline=deadline)
        environment = C.clean_environment(work)
        original = {str(path): directory_identity(path) for path in (root, work, public, root / "cases")}

        def source_check(label):
            C.conventional_host(D)
            D.need(all(directory_identity(Path(path)) == item for path, item in original.items()), "Shell task root changed")
            head = check.command(label + "-head", ["/usr/bin/git", "rev-parse", "HEAD"], environment, source, timeout=15)
            status = check.command(label + "-status", ["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                                   environment, source, timeout=15)
            D.need(head.stdout == sha.encode("ascii") + b"\n" and head.stderr == status.stdout == status.stderr == b"",
                   "Shell source is not the exact original clean checkout")

        source_check("before")
        tools_inputs = shell_tools_inputs_for_observation()
        policy = installed_shell_os_inputs(check, work, native, compiler, old_compiler)
        check.phase = "shell-handoff"
        lifecycle = local("ubuntu_publication_lifecycle")
        policy = lifecycle.compact_shell_loader_policy(policy, compiler)
        # Compile-only dependency/unit evidence stays in its already admitted
        # original artifact. The root service receives only the relevant typed
        # projection, plus the full original record's content binding.
        projection = {key: compiler[key] for key in ("sourceSha", "sourceTree", "runId", "attempt", "features",
            "manifestSha256", "protocolSha256", "exportedArtifacts", "nativeRecord", "frontendRecord")}
        projection["originalRecord"] = D.file_record(work / "admitted-shell/compiler.json", SHELL_METADATA_LIMIT)
        shell = {"binaries": binaries, "compiler": projection, "rosterSha256": roster_sha,
                 "producerAttempt": producer_attempt, "artifactId": artifact_id, "acceptedU": accepted, "loaderPolicy": policy}
        source_record = {"sourceSha": sha, "sourceTree": compiler["sourceTree"], "runId": os.environ["GITHUB_RUN_ID"],
            "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "features": SHELL_FEATURES, "acceptedU": accepted,
            "shellRosterSha256": roster_sha, "shellProducerAttempt": producer_attempt, "shellArtifactId": artifact_id,
            "platformLibrarySourceSha": old_compiler["sourceSha"], "imageOS": os.environ["ImageOS"],
            "imageVersion": os.environ["ImageVersion"], "originalDeadline": repr(deadline), "qualified": False,
            "toolsInputPreparation": tools_inputs}
        D.write(public / "source.json", D.canonical(source_record))
        request = {"sourceSha": sha, "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "deadline": deadline, "runnerUid": os.getuid(), "runnerGid": os.getgid(), "source": str(source), "taskRoot": str(root),
            "library": library, "packages": packages, "compilerRecords": old_compiler, "shell": shell}
        raw = shell_handoff_bytes(request, deadline)
        path = work / "lifecycle-handoff.json"
        pin = D.write(path, raw)
        argv = lifecycle.service_argv(path, pin["sha256"], entry_sha)
        client = check.command("root-shell-connection", argv,
            {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(work / "home")},
            work, timeout=1200, limit=2 << 20)
        observed = lifecycle.verify_service_result(path, pin["sha256"], entry_sha, client, public)
        project_draft = shell_project_draft_observation(observed, lifecycle)
        source_check("after")
        D.need(D.canonical(shell_tools_inputs_for_observation()) == D.canonical(tools_inputs),
               "Original Tools input preparation or live Git/Python/JDK nodes changed during shell observations")
        D.need(time.monotonic() < deadline, "Original shell result endpoint expired")
        D.write(public / "result.json", D.canonical({**source_record, "lifecycle": observed,
            "projectDraft": project_draft, "candidateDocuments": observed["candidateDocuments"], "projectPaths": observed["projectPaths"],
            "workflowApply": observed["workflowApply"], "sessionInputs": observed["sessionInputs"], "metadataSave": observed["metadataSave"],
            "toolsOffline": observed["toolsOffline"], "toolsOfflineQualificationOnly": True, "offlineFullWorkDeadlineExercised": False,
            "settledFailure": observed["settledFailure"],
            "commands": check.commands, "cases": list(lifecycle.SHELL_CASES), "compilerRerun": False,
            "supplierRebuilt": False, "packageBuilt": False, "upgradeOrRefusalRerun": False,
            "scope": "normal-shell-to-accepted-installed-runtime-connection-only"}))
        D.need(time.monotonic() < deadline, "Original shell result close/readback was late")
        print("Normal window, seventeen success-requiring observers and one raw-exit1 expected negative retained with service finality; no product/package qualification.", flush=True)
    except BaseException as error:
        retain_failure(root, phase if check is None else check.phase, [] if check is None else check.commands, error)
        raise


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["prepare"]:
            prepare()
        elif sys.argv[1:] == ["installed-compile"]:
            verify(installed_compile=True)
        elif sys.argv[1:] == ["installed"]:
            verify_installed()
        elif sys.argv[1:] == ["installed-shell-compile"]:
            verify_installed_shell_compile()
        elif sys.argv[1:] == ["installed-shell"]:
            verify_installed_shell()
        elif sys.argv[1:] == ["installed-shell-tools-namespace-before"]:
            shell_tools_namespace_snapshot()
        elif sys.argv[1:] == ["installed-shell-tools-namespace-check"]:
            shell_tools_namespace_check()
        elif sys.argv[1:] == ["installed-shell-tools-before"]:
            shell_tools_input_snapshot("before")
        elif sys.argv[1:] == ["installed-shell-tools-after"]:
            shell_tools_input_snapshot("after")
        else:
            D.need(len(sys.argv) == 1, "Expected a fixed preparation/compiler/installed entry or no-argument lifecycle entry")
            verify()
    except Exception as error:
        print("Publisher check refused: " + failure_reason(error) + ". Preserve original evidence; no qualification.", file=sys.stderr)
        raise SystemExit(1)
