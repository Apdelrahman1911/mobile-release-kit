"""Finite setup-PR policy, not credential, process, filesystem or consent authority.

Only the original native GitHub connection may supply an exchange and a durable
journal. These helpers deliberately have no live factory, CLI or API service
registration: a parsed target or successful pure test cannot publish anything.
The five-file scope never includes local Git state, version, metadata or app code.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _repository
from .api._github_setup import _resource
from .config import validate_config_data
from .errors import ConfigurationError
from .github_preflight import HttpRequest, TOOLING_REPOSITORY, _DIGEST, _MARKER, _SHA, _match, _object, _quote, _require, branch
from .workflow_payloads import GITHUB_WORKFLOWS, canonical_workflow_reference, render_workflow_caller

PROTOCOL = "mrk-github-setup-publication/1"
CONFIG_PATH = "release/mobile-release.json"
PATHS = (CONFIG_PATH, *(path for _, path in GITHUB_WORKFLOWS))
MAX_CONFIG_BYTES = 64 * 1024  # This review explicitly refuses larger configurations.
MAX_CALLER_BYTES = 16 * 1024
MAX_REVIEW_BYTES = 384 * 1024
MAX_TREE_BYTES = 256 * 1024
MAX_TREE_ENTRIES = 1000
MAX_REQUESTS = 24
PHASES = ("tree", "commit", "branch", "pull")
REASONS = frozenset({"target-changed", "source-changed", "caller-mismatch", "source-unsupported",
    "configuration-invalid", "response-invalid", "response-limit", "no-change", "branch-exists",
    "unauthorized", "forbidden", "not-found-or-inaccessible", "rate-limited", "network-unavailable",
    "tls-failed", "expired", "cancelled", "journal-unavailable", "unresolved", "ambiguous"})
CONFIRMATION = ("Create this five-file setup commit on a NEW branch and open a draft pull request? "
    "Only release/mobile-release.json and four canonical workflow callers are included. "
    "Version, metadata and application source changes are NOT uploaded. Local Git/index/HEAD are unchanged. "
    "Push and pull-request events can start the repository's existing CI. No merge, existing-branch update, "
    "workflow dispatch or release is requested. Cancellation does not undo a sent request.")


class Refused(ValueError):
    def __init__(self, reason: str):
        _require(reason in REASONS)
        self.reason = reason
        super().__init__("The bounded setup publication was refused")


def _need(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise Refused(reason)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _fingerprint(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def git_hash(kind: str, raw: bytes) -> str:
    _require(kind in {"blob", "tree"} and type(raw) is bytes)
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    base: str
    tooling_sha: str
    marker: str

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "base",
                              "toolingRepository", "toolingSha", "marker"})
        _require(row["toolingRepository"] == TOOLING_REPOSITORY)
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), branch(row["base"]),
                   _match(row["toolingSha"], _SHA), _match(row["marker"], _MARKER))

    def value(self) -> dict:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id, "base": self.base,
                "toolingRepository": TOOLING_REPOSITORY, "toolingSha": self.tooling_sha, "marker": self.marker}

    @property
    def head(self) -> str:
        return "mrk/setup-" + self.marker

    @property
    def title(self) -> str:
        return "MobileReleaseKit setup [" + self.marker + "]"


@dataclass(frozen=True, slots=True, repr=False)
class Source:
    """Exact saved bytes supplied by the existing capture; this object is DATA."""
    files: tuple[bytes, ...]
    templates: tuple[bytes, ...]

    @classmethod
    def from_saved(cls, raw: bytes, target: Target) -> Source:
        Target.parse(target.value())
        try:
            _need(type(raw) is bytes and 0 < len(raw) <= MAX_CONFIG_BYTES, "configuration-invalid")
            config = _decode_json(raw, limit=MAX_CONFIG_BYTES, nodes=20000, depth=32, exact=True)
            validate_config_data(config)
            _, resource = _resource()
            templates = tuple(resource["workflows"][name].encode("utf-8") for name, _ in GITHUB_WORKFLOWS)
            files = (raw, *(render_workflow_caller(template, TOOLING_REPOSITORY, target.tooling_sha)
                           for template in templates))
            _need(all(0 < len(item) <= MAX_CALLER_BYTES for item in files[1:]), "response-limit")
            return cls(files, templates)
        except (ValueError, TypeError, UnicodeError, ConfigurationError):
            raise Refused("configuration-invalid") from None


# Flattened selected Git trees. Values are (mode, SHA); unrelated subtrees are
# preserved as opaque Git objects, not traversed or downloaded.
Tree = dict[str, tuple[str, str]]


def _path(value: object) -> str:
    _need(type(value) is str and 0 < len(value.encode("utf-8")) <= 1024, "source-unsupported")
    parts = value.split("/")
    _need(len(parts) <= 32 and all(part not in {"", ".", "..", ".git"} and "\0" not in part
          for part in parts), "source-unsupported")
    return value


def tree_hash(entries: Tree, *, verify_subtrees: bool = False) -> str:
    """Compute Git's tree identity, retaining opaque, unexpanded directories.

    Only directories whose immediate entries are present are recomputed. This
    also supports a complete tree, but does not require reading unrelated app
    source merely to change five setup files. Empty fetched trees are verified
    by _tree and keep their already authenticated empty-tree object identity.
    """
    children: dict[str, dict[str, tuple[str, str]]] = {"": {}}
    for path, (mode, sha) in entries.items():
        _path(path); _match(sha, _SHA)
        parent, _, name = path.rpartition("/")
        _need(mode in {"040000", "100644", "100755", "120000", "160000"}, "source-unsupported")
        _need(not parent or parent in entries and entries[parent][0] == "040000", "source-unsupported")
        children.setdefault(parent, {})[name] = (mode, sha)
    hashes: dict[str, str] = {}
    for parent in sorted(children, key=lambda key: key.count("/") + bool(key), reverse=True):
        raw = bytearray()
        for name, (mode, sha) in sorted(children[parent].items(),
                key=lambda row: row[0].encode("utf-8") + (b"/" if row[1][0] == "040000" else b"")):
            if mode == "040000":
                child = (parent + "/" if parent else "") + name
                if child in hashes:
                    actual = hashes[child]
                    _need(not verify_subtrees or actual == sha, "source-changed")
                    sha = actual
            raw.extend(mode.lstrip("0").encode("ascii") + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(sha))
        hashes[parent] = git_hash("tree", bytes(raw))
    return hashes[""]


def _tree(body: Any, expected: str) -> Tree:
    """One complete *nonrecursive* directory response, bound to its Git SHA."""
    _need(type(body) is dict and body.get("sha") == expected and body.get("truncated") is False)
    rows = body.get("tree")
    _need(type(rows) is list and len(rows) <= MAX_TREE_ENTRIES, "source-unsupported")
    _need(len(_canonical(body)) <= MAX_TREE_BYTES, "response-limit")
    result: Tree = {}
    for row in rows:
        _need(type(row) is dict)
        path = _path(row.get("path")); mode = row.get("mode"); sha = _match(row.get("sha"), _SHA)
        _need("/" not in path and path not in result, "source-unsupported")
        _need(row.get("type") == ("tree" if mode == "040000" else "commit" if mode == "160000" else "blob"))
        result[path] = (mode, sha)
    _need(tree_hash(result, verify_subtrees=True) == expected, "source-changed")
    return result


def _replace_tree(tree: Tree, source: Source) -> Tree:
    result = dict(tree)
    for path, raw in zip(PATHS, source.files, strict=True):
        pieces = path.split("/")
        for count in range(1, len(pieces)):
            parent = "/".join(pieces[:count])
            _need(parent not in result or result[parent][0] == "040000", "source-unsupported")
            result.setdefault(parent, ("040000", "0" * 40))
        _need(path not in result or result[path][0] == "100644", "source-unsupported")
        result[path] = ("100644", git_hash("blob", raw))
    return result


@dataclass(frozen=True, slots=True, repr=False)
class Prepared:
    target: Target
    base_commit: str
    base_tree: str
    desired_tree: str
    source: Source
    before: tuple[bytes | None, ...]

    @classmethod
    def parse(cls, value: object) -> Prepared:
        """Closed retained review DATA, not renderer consent or tree authority."""
        row = _object(value, {"protocol", "target", "baseCommit", "baseTree", "desiredTree",
                              "files", "head", "confirmation"})
        target = Target.parse(row["target"])
        _require(row["protocol"] == PROTOCOL and row["head"] == target.head
                 and row["confirmation"] == CONFIRMATION)
        files = row["files"]
        _require(type(files) is list and len(files) == len(PATHS))
        before, after = [], []
        for index, (item, path) in enumerate(zip(files, PATHS, strict=True)):
            _object(item, {"path", "before", "after"})
            limit = MAX_CONFIG_BYTES if index == 0 else MAX_CALLER_BYTES
            _require(item["path"] == path and type(item["after"]) is str)
            new = item["after"].encode("utf-8")
            _require(0 < len(new) <= limit)
            old = item["before"]
            _require(old is None or type(old) is str)
            old = None if old is None else old.encode("utf-8")
            _require(old is None or 0 < len(old) <= limit)
            before.append(old); after.append(new)
        source = Source.from_saved(after[0], target)
        _require(source.files == tuple(after))
        for index, old in enumerate(before):
            if old is None:
                continue
            if index:
                _require(canonical_workflow_reference(source.templates[index - 1], old) is not None)
            else:
                validate_config_data(_decode_json(old, limit=MAX_CONFIG_BYTES, nodes=20000, depth=32, exact=True))
        result = cls(target, _match(row["baseCommit"], _SHA), _match(row["baseTree"], _SHA),
                     _match(row["desiredTree"], _SHA), source, tuple(before))
        _require(result.base_tree != result.desired_tree and result.view() == row)
        return result

    def summary(self) -> dict:
        """Nonsecret durable identity only; never serialize config/caller text here."""
        return {"protocol": PROTOCOL, "target": self.target.value(), "baseCommit": self.base_commit,
                "baseTree": self.base_tree, "desiredTree": self.desired_tree,
                "files": [{"path": path, "after": _fingerprint(after),
                           "before": None if before is None else _fingerprint(before)}
                          for path, before, after in zip(PATHS, self.before, self.source.files, strict=True)]}

    def view(self) -> dict:
        result = {**self.summary(), "head": self.target.head, "confirmation": CONFIRMATION,
                  "files": [{"path": path, "before": None if old is None else old.decode("utf-8"),
                             "after": new.decode("utf-8")}
                            for path, old, new in zip(PATHS, self.before, self.source.files, strict=True)]}
        _need(len(_canonical(result)) <= MAX_REVIEW_BYTES, "response-limit")
        return result


class Exchange(Protocol):
    def __call__(self, request: HttpRequest) -> ReadResult: ...


class Journal(Protocol):
    """Must be supplied by the original durable owner, never by a renderer."""
    def create_intent(self, summary: dict) -> None: ...
    def claim_write(self, phase: str) -> None: ...
    def record(self, phase: str, identity: str) -> None: ...


class Operation:
    """One finite original request sequence. Reusing a request claim is forbidden."""
    def __init__(self, target: Target, exchange: Exchange):
        self.target = Target.parse(target.value())
        self.exchange = exchange
        self.steps: set[str] = set()
        self.control = _control()
        self.prefix = "/repos/" + self.target.repository

    def take(self, step: str, path: str, *, body: dict | None = None, absent: bool = False,
             array: bool = False) -> Any:
        _need(step not in self.steps and len(self.steps) < MAX_REQUESTS)
        self.steps.add(step)
        raw = None if body is None else _canonical(body)
        _need(raw is None or len(raw) <= MAX_REVIEW_BYTES, "response-limit")
        response = self.exchange(HttpRequest("GET" if body is None else "POST", path, raw))
        _need(type(response) is ReadResult)
        control = _check_control(response.control)
        self.control = dict(control)
        if control["reason"] != "none":
            raise Refused(control["reason"])
        row = _object(response.observation, {"status", "body", "failure"})
        if row["failure"] != "none":
            raise Refused(row["failure"])
        code = row["status"]
        _need(type(code) is int)
        if code == 404 and absent:
            _need(row["body"] is None)
            return None
        expected = 200 if body is None else 201
        if code != expected:
            raise Refused({401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible",
                           409: "source-changed", 422: "source-changed", 429: "rate-limited"}.get(code,
                          "network-unavailable" if code >= 500 else "response-invalid"))
        value = row["body"]
        _need(type(value) is (list if array else dict))
        _need(len(_canonical(value)) <= MAX_REVIEW_BYTES, "response-limit")
        return value

    def identities(self, suffix: str = "") -> None:
        if not suffix:
            account = self.take("account", "/user")
            _need(type(account.get("id")) is int and _account(account)["id"] == self.target.account_id,
                  "target-changed")
        repository = self.take("repository" + suffix, self.prefix)
        _need(type(repository.get("id")) is int, "target-changed")
        selected = _repository(repository)
        _need(selected["id"] == self.target.repository_id
              and selected["fullName"].lower() == self.target.repository.lower()
              and not selected["archived"], "target-changed")

    def ref(self, step: str, name: str, *, absent: bool = False) -> str | None:
        row = self.take(step, self.prefix + "/git/ref/heads/" + _quote(name), absent=absent)
        if row is None:
            return None
        _need(row.get("ref") == "refs/heads/" + name and type(row.get("object")) is dict, "source-changed")
        _need(row["object"].get("type") == "commit", "source-changed")
        return _match(row["object"].get("sha"), _SHA)


def prepare(target: Target, source: Source, exchange: Exchange) -> Prepared:
    # Reconstruct from original bytes: a forged Source cannot add a sixth path.
    _need(type(source) is Source and len(source.files) == 5)
    _need(Source.from_saved(source.files[0], target) == source, "configuration-invalid")
    op = Operation(target, exchange)
    op.identities()
    base = op.ref("base", target.base)
    _need(base is not None)
    commit = op.take("base-commit", op.prefix + "/git/commits/" + base)
    _need(commit.get("sha") == base and type(commit.get("tree")) is dict, "source-changed")
    tree_sha = _match(commit["tree"].get("sha"), _SHA)
    tree = _tree(op.take("tree", op.prefix + "/git/trees/" + tree_sha), tree_sha)
    # Only ancestors of the five fixed paths are expanded. The Git tree API's
    # nonrecursive response preserves every sibling object without fetching its
    # descendants. Every fetched directory is independently checked against the
    # object ID carried by its already verified parent.
    for index, parent in enumerate((".github", ".github/workflows", "release")):
        if parent not in tree:
            continue
        mode, sha = tree[parent]
        _need(mode == "040000", "source-unsupported")
        children = _tree(op.take("tree-" + str(index), op.prefix + "/git/trees/" + sha), sha)
        tree.update((parent + "/" + name, entry) for name, entry in children.items())
    replaced = _replace_tree(tree, source)
    old: list[bytes | None] = []
    for index, path in enumerate(PATHS):
        if path not in tree:
            old.append(None)
            continue
        mode, sha = tree[path]
        _need(mode == "100644", "source-unsupported")
        blob = op.take("blob-" + str(index), op.prefix + "/git/blobs/" + sha)
        _need(blob.get("sha") == sha and blob.get("encoding") == "base64")
        text, size = blob.get("content"), blob.get("size")
        limit = MAX_CONFIG_BYTES if index == 0 else MAX_CALLER_BYTES
        _need(type(text) is str and type(size) is int and 0 < size <= limit, "source-unsupported")
        raw = base64.b64decode(text.replace("\n", ""), validate=True)
        _need(len(raw) == size and git_hash("blob", raw) == sha, "source-changed")
        raw.decode("utf-8")
        if index:
            _need(canonical_workflow_reference(source.templates[index - 1], raw) is not None, "caller-mismatch")
        else:
            validate_config_data(_decode_json(raw, limit=MAX_CONFIG_BYTES, nodes=20000, depth=32, exact=True))
        old.append(raw)
    _need(op.ref("base-after", target.base) == base, "source-changed")
    _need(op.ref("head-absent", target.head, absent=True) is None, "branch-exists")
    op.identities("-after")
    desired = tree_hash(replaced)
    _need(desired != tree_sha, "no-change")
    result = Prepared(target, base, tree_sha, desired, source, tuple(old))
    result.view()  # Complete display must fit before exposing a confirmation.
    return result


def _commit(body: dict, prepared: Prepared, expected: str | None = None) -> str:
    sha = _match(body.get("sha"), _SHA)
    _need(expected is None or sha == expected, "source-changed")
    _need(body.get("message") == prepared.target.title and type(body.get("tree")) is dict
          and body["tree"].get("sha") == prepared.desired_tree, "source-changed")
    parents = body.get("parents")
    _need(type(parents) is list and len(parents) == 1 and type(parents[0]) is dict
          and parents[0].get("sha") == prepared.base_commit, "source-changed")
    return sha


def _pull(body: dict, target: Target, base_commit: str, commit: str) -> dict:
    number = _id(body.get("number"), upstream=True)
    _need(body.get("title") == target.title and body.get("draft") is True
          and body.get("state") == "open" and body.get("merged_at") is None, "source-changed")
    _need(type(body.get("user")) is dict and _id(body["user"].get("id"), upstream=True) == target.account_id,
          "target-changed")
    for key, name, sha in (("head", target.head, commit), ("base", target.base, base_commit)):
        row = body.get(key)
        _need(type(row) is dict and row.get("ref") == name and row.get("sha") == sha
              and type(row.get("repo")) is dict, "source-changed")
        _need(_id(row["repo"].get("id"), upstream=True) == target.repository_id
              and row["repo"].get("full_name", "").lower() == target.repository.lower(), "target-changed")
    url = "https://github.com/" + target.repository + "/pull/" + number
    _need(body.get("html_url") == url)
    return {"number": number, "url": url, "commit": commit}


def publish(prepared: Prepared, source: Source, exchange: Exchange, journal: Journal) -> dict:
    """Requires original native consent/custody outside this pure policy layer.

    A claimed write is potentially effective even when its reply is lost. The
    durable journal MUST refuse any repeated intent/phase; no retry API exists.
    """
    _need(type(prepared) is Prepared and type(source) is Source and source == prepared.source,
          "source-changed")
    _need(Source.from_saved(source.files[0], prepared.target) == source, "configuration-invalid")
    prepared.view()
    result = {"effect": "not-sent", "reason": "none", "claimed": [], "confirmed": {}, "pull": None,
              "control": _control()}
    op = Operation(prepared.target, exchange)
    try:
        op.identities()
        _need(op.ref("base", prepared.target.base) == prepared.base_commit, "source-changed")
        _need(op.ref("head-absent", prepared.target.head, absent=True) is None, "branch-exists")
        journal.create_intent(prepared.summary())

        def write(phase: str, endpoint: str, body: dict) -> dict:
            journal.claim_write(phase)
            result["claimed"].append(phase)
            result["effect"] = "potentially-applied"
            return op.take("write-" + phase, op.prefix + endpoint, body=body)

        tree = write("tree", "/git/trees", {"base_tree": prepared.base_tree,
            "tree": [{"path": path, "mode": "100644", "type": "blob", "content": raw.decode("utf-8")}
                     for path, raw in zip(PATHS, source.files, strict=True)]})
        _need(tree.get("sha") == prepared.desired_tree, "source-changed")
        journal.record("tree", prepared.desired_tree)
        result["confirmed"]["tree"] = prepared.desired_tree
        commit = _commit(write("commit", "/git/commits", {"message": prepared.target.title,
            "tree": prepared.desired_tree, "parents": [prepared.base_commit]}), prepared)
        journal.record("commit", commit)
        result["confirmed"]["commit"] = commit
        _need(op.ref("base-before-ref", prepared.target.base) == prepared.base_commit, "source-changed")
        ref = write("branch", "/git/refs", {"ref": "refs/heads/" + prepared.target.head, "sha": commit})
        _need(ref.get("ref") == "refs/heads/" + prepared.target.head and type(ref.get("object")) is dict
              and ref["object"].get("type") == "commit" and ref["object"].get("sha") == commit, "source-changed")
        _need(op.ref("head-after", prepared.target.head) == commit, "source-changed")
        journal.record("branch", commit)
        result["confirmed"]["branch"] = commit
        _need(op.ref("base-before-pr", prepared.target.base) == prepared.base_commit, "source-changed")
        pull = _pull(write("pull", "/pulls", {"title": prepared.target.title, "head": prepared.target.head,
            "base": prepared.target.base, "body": CONFIRMATION, "draft": True}),
            prepared.target, prepared.base_commit, commit)
        journal.record("pull", pull["number"])
        result["confirmed"]["pull"] = pull["number"]
        op.identities("-after")
        result.update(effect="draft-pr-observed", pull=pull)
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    except OSError:
        result["reason"] = "journal-unavailable"
    result["control"] = op.control
    return result


def reconcile(summary: dict, confirmed: dict, claimed: tuple[str, ...], exchange: Exchange) -> dict:
    """Read-only inspection of durable original identity, never a write retry.

    Orphan tree/commit objects with a lost reply cannot be searched reliably:
    they remain unresolved. No branch/PR is adopted without its durable claim.
    """
    target = Target.parse(summary["target"])
    _need(summary.get("protocol") == PROTOCOL and type(confirmed) is dict
          and tuple(PHASES[:len(claimed)]) == claimed and set(confirmed) <= set(claimed))
    base = _match(summary.get("baseCommit"), _SHA)
    tree = _match(summary.get("desiredTree"), _SHA)
    result = {"effect": "unresolved", "reason": "unresolved", "pull": None, "control": _control()}
    if "branch" not in claimed or "commit" not in confirmed:
        return result
    commit = _match(confirmed["commit"], _SHA)
    op = Operation(target, exchange)
    try:
        op.identities()
        _need(op.ref("head", target.head, absent=True) == commit, "unresolved")
        row = op.take("commit", op.prefix + "/git/commits/" + commit)
        _need(row.get("sha") == commit and row.get("message") == target.title
              and type(row.get("tree")) is dict and row["tree"].get("sha") == tree
              and type(row.get("parents")) is list and len(row["parents"]) == 1
              and row["parents"][0].get("sha") == base, "source-changed")
        result["effect"] = "branch-observed"
        if "pull" not in claimed:
            result["control"] = op.control
            return result
        pulls = op.take("pulls", op.prefix + "/pulls?state=all&head="
                        + _quote(target.repository.split("/")[0] + ":" + target.head)
                        + "&base=" + _quote(target.base) + "&per_page=2&page=1", array=True)
        _need(len(pulls) == 1, "ambiguous" if len(pulls) > 1 else "unresolved")
        pull = _pull(pulls[0], target, base, commit)
        _need("pull" not in confirmed or confirmed["pull"] == pull["number"], "source-changed")
        op.identities("-after")
        result.update(effect="draft-pr-observed", reason="none", pull=pull)
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    result["control"] = op.control
    return result
