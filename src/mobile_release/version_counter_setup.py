"""First counter policy on the ORIGINAL publication transport and journal.

No token factory, filesystem, process, remote reset, allocator or enrollment.
The selected native publication owns source/state/consent and all finality.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace

from . import github_setup_publication as publication
from . import version_allocation as allocation
from . import version_text
from ._github_connection_transport import ReadFailure, _control
from .api._github_connection import _account, _repository
from .github_setup_secret_inputs import SecretConfigurationError
from .config import release_version_from_values

PROTOCOL = "mrk-version-counter-setup/1"
PURPOSE = "version-counter"
PHASES = ("tree", "commit", "branch")
MAX_LEDGER_BYTES = 8192
MAX_VERSION_BYTES = 65536
REASONS = frozenset({"counter-exists", "counter-intent-exists", "counter-state-unavailable",
                     "counter-state-changed", "counter-known-authority", "counter-version-unsupported"})
CONFIRMATION = ("Create the FIRST shared version counter on the fixed NEW mrk-version-allocations branch? "
    "The initial version is saved project data, NOT a verified Store floor. Existing repository automation "
    "may run. No allocation, protection change, enrollment, reset or Store request is authorized. "
    "Known prior counters refuse; deleted history on another computer cannot be ruled out. "
    "Cancellation does not undo a sent request.")


class Refused(publication.Refused):
    def __init__(self, reason: str):
        if reason not in REASONS:
            super().__init__(reason)
        else:
            self.reason = reason
            ValueError.__init__(self, "The first shared counter was refused")


def need(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise Refused(reason)


def fingerprint(value: object, maximum: int) -> dict:
    row = publication._object(value, {"bytes", "sha256"})
    need(type(row["bytes"]) is int and 0 < row["bytes"] <= maximum)
    publication._match(row["sha256"], publication._DIGEST)
    return dict(row)


@dataclass(frozen=True, slots=True, repr=False)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    base: str
    marker: str
    project_id: str | None
    ledger_id: str
    version: allocation.ReleaseVersion
    config_bytes: int
    config_sha256: str
    version_path: str
    version_bytes: int
    version_sha256: str

    @classmethod
    def parse(cls, value: object, *, unresolved: bool = False) -> Target:
        row = publication._object(value, {"purpose", "projectBinding", "repository", "accountId",
            "repositoryId", "base", "marker", "projectId", "ledgerId", "initialVersion",
            "savedConfig", "savedVersion"})
        need(row["purpose"] == PURPOSE)
        config = fingerprint(row["savedConfig"], publication.MAX_CONFIG_BYTES)
        version = publication._object(row["savedVersion"], {"path", "bytes", "sha256"})
        measured = fingerprint({k: version[k] for k in ("bytes", "sha256")}, MAX_VERSION_BYTES)
        from .api._release_version import _source_path
        path = version["path"]
        need(type(path) is str and len(path.encode("utf-8")) <= version_text.MAX_RELATIVE_BYTES
             and len(path.split("/")) <= version_text.MAX_COMPONENTS and _source_path(path))
        base = publication.branch(row["base"])
        need(base != allocation.LEDGER_BRANCH, "source-unsupported")
        try:
            # Only the counter-private Prepare target can carry required-null.
            # No Genesis or review is created until the SAME original native
            # state lease supplies this ID in its authenticated GO frame.
            project_id = row["projectId"]
            if project_id is None:
                need(unresolved)
            else:
                allocation._project_id(project_id)
            repository_id = allocation._id(row["repositoryId"])
            ledger_id = allocation._uuid(row["ledgerId"])
            version_value = allocation.policy.parse_version(row["initialVersion"], ("android",), automatic=True)
        except (ValueError, TypeError):
            raise Refused("counter-version-unsupported") from None
        return cls(publication._match(row["projectBinding"], publication._DIGEST),
            publication._coordinate(row["repository"]), publication._id(row["accountId"]),
            repository_id, base, publication._match(row["marker"], publication._MARKER),
            project_id, ledger_id, version_value, config["bytes"],
            config["sha256"], path, measured["bytes"], measured["sha256"])

    def value(self) -> dict:
        return {"purpose": PURPOSE, "projectBinding": self.project_binding, "repository": self.repository,
            "accountId": self.account_id, "repositoryId": self.repository_id, "base": self.base,
            "marker": self.marker, "projectId": self.project_id, "ledgerId": self.ledger_id,
            "initialVersion": allocation.policy.version_value(self.version),
            "savedConfig": {"bytes": self.config_bytes, "sha256": self.config_sha256},
            "savedVersion": {"path": self.version_path, "bytes": self.version_bytes,
                             "sha256": self.version_sha256}}

    @property
    def head(self) -> str:
        return allocation.LEDGER_BRANCH

    @property
    def title(self) -> str:
        return "MobileReleaseKit first version counter [" + self.marker + "]"

    def genesis(self) -> allocation.Genesis:
        need(self.project_id is not None)
        return allocation.Genesis(self.project_id, self.repository_id, self.ledger_id, self.version)

    def ledger(self) -> bytes:
        ledger = allocation.Ledger(self.genesis(), ())
        raw = ledger.to_bytes()
        need(len(raw) <= MAX_LEDGER_BYTES)
        # to_bytes is the existing canonical empty-ledger codec. Ledger.parse
        # intentionally requires ENROLLED protection authority; never fabricate
        # that authority merely to reparse our own unprotected setup bytes.
        return raw


def target(value: object, *, unresolved: bool = False):
    """Two closed grammars; unknown purpose is never the legacy default."""
    if type(value) is dict and "purpose" in value:
        return Target.parse(value, unresolved=unresolved)
    return publication.Target.parse(value)


def resolved_matches(original, actual) -> bool:
    if type(original) is Target and type(actual) is Target:
        return actual.project_id is not None and (original == actual or
            original.project_id is None and replace(actual, project_id=None) == original)
    return original == actual


@dataclass(frozen=True, slots=True, repr=False)
class NativeGo:
    target: Target
    review: object


def resolve_go(original: Target, value: object, review) -> NativeGo:
    allocation._project_id(value)
    actual = Target.parse(replace(original, project_id=value).value())
    need(resolved_matches(original, actual))
    need(review is None or type(review) is Prepared and review.target == actual)
    return NativeGo(actual, review)


def prepared(value: object):
    if type(value) is dict and value.get("protocol") == PROTOCOL:
        return Prepared.parse(value)
    return publication.Prepared.parse(value)


def source_matches(config: bytes, version: bytes, selected: Target) -> None:
    """Original held reader supplies both bytes, never a proposed UI version."""
    need(type(selected) is Target)
    need(publication._fingerprint(config) == selected.value()["savedConfig"], "source-changed")
    need(publication._fingerprint(version) == {"bytes": selected.version_bytes,
                                              "sha256": selected.version_sha256}, "source-changed")
    try:
        selection = version_text.public_version_selection(config.decode("utf-8"))
        need(selection.source == selected.version_path, "source-changed")
        original = version_text.original_text(selection, version)
        actual = release_version_from_values(dict(original.parsed), name_key=selection.name_key,
            build_key=selection.build_key, ios_enabled=selection.ios_enabled, source_label="saved version")
        need(actual == selected.version, "source-changed")
        selected.ledger()  # Existing Genesis automatic grammar, not normalization.
    except Refused:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise Refused("counter-version-unsupported") from None


def objects(selected: Target) -> tuple[bytes, str, str, str]:
    raw = selected.ledger()
    blob = publication.git_hash("blob", raw)
    release = publication.tree_hash({allocation.LEDGER_PATH.split("/")[1]: ("100644", blob)})
    root = publication.tree_hash({"release": ("040000", release)})
    return raw, blob, release, root


@dataclass(frozen=True, slots=True, repr=False)
class Prepared:
    target: Target
    base_commit: str
    base_tree: str

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = publication._object(value, {"protocol", "target", "baseCommit", "baseTree",
            "desiredTree", "ledgerBlob", "genesisSha256", "ledger", "head", "confirmation"})
        result = cls(Target.parse(row["target"]), publication._match(row["baseCommit"], publication._SHA),
                     publication._match(row["baseTree"], publication._SHA))
        need(result.view() == row)
        return result

    @property
    def desired_tree(self) -> str:
        return objects(self.target)[3]

    def summary(self) -> dict:
        raw, blob, _, root = objects(self.target)
        return {"protocol": PROTOCOL, "target": self.target.value(), "baseCommit": self.base_commit,
            "baseTree": self.base_tree, "desiredTree": root, "ledgerBlob": blob,
            "genesisSha256": self.target.genesis().sha256, "ledger": publication._fingerprint(raw)}

    def view(self) -> dict:
        return self.summary() | {"ledger": self.target.ledger().decode("utf-8"),
                                 "head": self.target.head, "confirmation": CONFIRMATION}


def summary(value: object) -> dict:
    row = publication._object(value, {"protocol", "target", "baseCommit", "baseTree",
        "desiredTree", "ledgerBlob", "genesisSha256", "ledger"})
    actual = Prepared(Target.parse(row["target"]), publication._match(row["baseCommit"], publication._SHA),
                      publication._match(row["baseTree"], publication._SHA)).summary()
    need(actual == row and len(publication._canonical(actual)) <= MAX_LEDGER_BYTES)
    return actual


def first_use(records: dict, selected: Target) -> None:
    """COMPLETE original 64-row roster, not account-filtered pending DATA."""
    need(type(records) is dict and len(records) <= 64, "journal-unavailable")
    for record in records.values():
        original = record["summary"]
        if original["protocol"] == PROTOCOL:
            old = Target.parse(summary(original)["target"])
            need(old.repository_id != selected.repository_id and
                 old.project_binding != selected.project_binding, "counter-intent-exists")


class Operation(publication.Operation):
    """Only policy/target differs. Same finite take/ref and HTTP control owner."""
    def __init__(self, selected: Target, exchange):
        self.target = Target.parse(selected.value())
        self.exchange, self.steps, self.control = exchange, set(), _control()
        self.prefix = "/repos/" + self.target.repository

    def account(self, suffix: str = "") -> None:
        row = self.take("account" + suffix, "/user")
        need(type(row.get("id")) is int and _account(row)["id"] == self.target.account_id, "target-changed")

    def repository(self, suffix: str = "") -> None:
        row = self.take("repository" + suffix, self.prefix)
        need(type(row.get("id")) is int, "target-changed")
        actual = _repository(row)
        need(actual["id"] == self.target.repository_id and
             actual["fullName"].lower() == self.target.repository.lower() and not actual["archived"],
             "target-changed")

    def source(self, expected: str | None = None) -> tuple[str, str]:
        sha = self.ref("source", self.target.base)
        need(expected is None or sha == expected, "source-changed")
        row = self.take("source-commit", self.prefix + "/git/commits/" + sha)
        need(row.get("sha") == sha and type(row.get("tree")) is dict, "source-changed")
        return sha, publication._match(row["tree"].get("sha"), publication._SHA)

    def counter_absent(self, step: str) -> None:
        need(self.ref(step, self.target.head, absent=True) is None, "counter-exists")

    def read_objects(self) -> None:
        raw, blob, release, root = objects(self.target)
        root_body = self.take("root-tree", self.prefix + "/git/trees/" + root)
        need(publication._tree(root_body, root) == {"release": ("040000", release)}, "source-changed")
        child = self.take("release-tree", self.prefix + "/git/trees/" + release)
        need(publication._tree(child, release) == {allocation.LEDGER_PATH.split("/")[1]: ("100644", blob)}, "source-changed")
        body = self.take("ledger-blob", self.prefix + "/git/blobs/" + blob)
        need(body.get("sha") == blob and body.get("encoding") == "base64" and
             type(body.get("size")) is int and body["size"] == len(raw) and type(body.get("content")) is str,
             "source-changed")
        content = body["content"]
        need(len(content) <= MAX_LEDGER_BYTES * 2 and "\r" not in content)
        decoded = base64.b64decode(content.replace("\n", ""), validate=True)
        need(decoded == raw and publication.git_hash("blob", decoded) == blob, "source-changed")

    def commit(self, sha: str, step: str) -> None:
        publication._match(sha, publication._SHA)
        row = self.take(step, self.prefix + "/git/commits/" + sha)
        need(row.get("sha") == sha and row.get("message") == self.target.title and
             type(row.get("tree")) is dict and row["tree"].get("sha") == objects(self.target)[3]
             and row.get("parents") == [], "source-changed")


def prepare(selected: Target, exchange, journal) -> Prepared:
    first_use(journal.publications, selected)
    op = Operation(selected, exchange)
    op.account(); op.repository()
    commit, tree = op.source()
    op.counter_absent("counter-absent")
    need(op.ref("source-after", selected.base) == commit, "source-changed")
    op.repository("-after"); op.account("-after")
    first_use(journal.publications, selected)
    need(len(op.steps) == 8)
    return Prepared(selected, commit, tree)


def observed(selected: Target, commit: str) -> dict:
    publication._match(commit, publication._SHA)
    return {"commit": commit, "ledgerId": selected.ledger_id, "genesisSha256": selected.genesis().sha256}


def publish(review: Prepared, exchange, journal) -> dict:
    Prepared.parse(review.view())
    selected = review.target
    result = {"effect": "not-sent", "reason": "none", "claimed": [], "confirmed": {},
              "counter": None, "control": _control()}
    op = Operation(selected, exchange)
    try:
        first_use(journal.publications, selected)
        op.account(); op.repository()
        need(op.source(review.base_commit) == (review.base_commit, review.base_tree), "source-changed")
        op.counter_absent("counter-absent")
        journal.create_intent(review.summary())

        def write(phase, path, value):
            journal.claim_write(phase)
            result["claimed"].append(phase)
            result["effect"] = "potentially-applied"
            return op.take("write-" + phase, op.prefix + path, body=value)

        raw, _, _, root = objects(selected)
        row = write("tree", "/git/trees", {"tree": [{"path": allocation.LEDGER_PATH,
            "mode": "100644", "type": "blob", "content": raw.decode("utf-8")}]})
        need(row.get("sha") == root, "source-changed")
        op.read_objects()
        journal.record("tree", root); result["confirmed"]["tree"] = root
        row = write("commit", "/git/commits", {"message": selected.title, "tree": root, "parents": []})
        commit = publication._match(row.get("sha"), publication._SHA)
        need(row.get("message") == selected.title and type(row.get("tree")) is dict and
             row["tree"].get("sha") == root and row.get("parents") == [], "source-changed")
        op.commit(commit, "commit-after")
        journal.record("commit", commit); result["confirmed"]["commit"] = commit
        need(op.ref("source-before-ref", selected.base) == review.base_commit, "source-changed")
        op.counter_absent("counter-before-ref")
        row = write("branch", "/git/refs", {"ref": "refs/heads/" + selected.head, "sha": commit})
        need(row.get("ref") == "refs/heads/" + selected.head and type(row.get("object")) is dict and
             row["object"].get("type") == "commit" and row["object"].get("sha") == commit, "source-changed")
        need(op.ref("counter-after", selected.head) == commit, "source-changed")
        op.commit(commit, "commit-final")
        op.account("-final"); op.repository("-final")
        need(op.ref("source-final", selected.base) == review.base_commit, "source-changed")
        need(op.ref("counter-final", selected.head) == commit and len(op.steps) == 20, "source-changed")
        journal.record("branch", commit); result["confirmed"]["branch"] = commit
        result.update(effect="counter-observed", counter=observed(selected, commit))
    except (publication.Refused, ReadFailure, SecretConfigurationError) as error:
        # Keep entered claims even when the same source checkpoint refuses.
        # Its enclosing original reader still owns POST and consuming close;
        # a failed close cannot become a usable publication result.
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    except OSError:
        result["reason"] = "journal-unavailable"
    result["control"] = op.control
    return result


def reconcile(original: dict, confirmed: dict, claimed: tuple[str, ...], exchange) -> dict:
    row = summary(original); selected = Target.parse(row["target"])
    need(type(confirmed) is dict and len(claimed) <= 3 and PHASES[:len(claimed)] == claimed and
         set(confirmed) <= set(claimed))
    result = {"effect": "unresolved", "reason": "unresolved", "counter": None, "control": _control()}
    if "branch" not in claimed or "commit" not in confirmed:
        return result
    commit = publication._match(confirmed["commit"], publication._SHA)
    op = Operation(selected, exchange)
    try:
        op.account(); op.repository()
        need(op.ref("counter", selected.head, absent=True) == commit, "unresolved")
        op.commit(commit, "commit"); op.read_objects()
        op.account("-final"); op.repository("-final")
        need(op.ref("counter-final", selected.head, absent=True) == commit and len(op.steps) <= 12, "unresolved")
        result.update(effect="counter-observed", reason="none", counter=observed(selected, commit))
    except (publication.Refused, ReadFailure, SecretConfigurationError) as error:
        # Keep entered claims even when the same source checkpoint refuses.
        # Its enclosing original reader still owns POST and consuming close;
        # a failed close cannot become a usable publication result.
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    result["control"] = op.control
    return result


def request_role(selected: Target, request):
    """Exact new purpose body grammar; legacy five-file roles are untouched."""
    from ._github_setup_publication_transport import validate_endpoint
    from ._github_connection_transport import _ResponseRole
    prefix = "/repos/" + selected.repository
    need(request.path == "/user" or request.path == prefix or request.path.startswith(prefix + "/"))
    role = _ResponseRole.PUBLICATION_CREATE if request.method == "POST" else _ResponseRole.PUBLICATION_READ
    validate_endpoint(role, request.method, request.path)
    tail = request.path[len(prefix) + 1:] if request.path.startswith(prefix + "/") else ""
    if request.method == "GET":
        need(request.body is None)
        if tail.startswith("git/ref/heads/"):
            need(tail.removeprefix("git/ref/heads/") in {publication._quote(selected.base), selected.head})
        return role
    need(type(request.body) is bytes and 0 < len(request.body) <= publication.MAX_REVIEW_BYTES)
    value = publication._decode_json(request.body, limit=publication.MAX_REVIEW_BYTES, nodes=128, depth=8, exact=True)
    _, _, _, root = objects(selected)
    if tail == "git/trees":
        need(value == {"tree": [{"path": allocation.LEDGER_PATH, "mode": "100644", "type": "blob",
                                "content": selected.ledger().decode("utf-8")}]})
    elif tail == "git/commits":
        need(value == {"message": selected.title, "tree": root, "parents": []})
    elif tail == "git/refs":
        row = publication._object(value, {"ref", "sha"})
        need(row["ref"] == "refs/heads/" + selected.head)
        publication._match(row["sha"], publication._SHA)
    else:
        raise Refused("response-invalid")
    return role
