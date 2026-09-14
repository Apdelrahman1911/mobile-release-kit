"""Fifteen finite foreign/manual cases without preceding healthy inventories."""
from __future__ import annotations

import copy
import os
from pathlib import Path

from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_catalog as catalog
from workflow import local_signing_semantic_fixture as semantic
from workflow.local_signing_workload import worker_timeout


def run_case(parent, identifier):
    case = catalog.case(identifier)
    assert case.kind == "focused" and case.variant in catalog.FOCUSED_VARIANTS
    variant = case.variant
    root = parent / "case"
    root.mkdir(mode=0o700)
    fixture.initialize(root, borrowed=variant == "borrowed-profile")
    context = fixture.pin_case_context(root)
    destination = root / "home/Library/MobileDevice/Provisioning Profiles" / (fixture.UUID + ".mobileprovision")
    seed_name = ("profile-unrecorded-stage" if variant.startswith("manual-") else
                 "completed" if variant.startswith("terminal-") else "active-after-build")

    def keep_profile(event):
        if variant == "terminal-profile-reappeared" and event["operation"] == "link" and event.get("succeeded") is True:
            os.link(destination, root / "retained-fictional-profile")

    if variant == "auto-add-ambiguous-create":
        selector = catalog.native("native-effect/create-search-add", operationKind="create", operationPhase="ARMED")
        fixture.require_fresh_recovery(root)
        semantic._new_step(root, "seed")
        original = fixture.run_worker(root, "seed", lambda: fixture.original_flow(root,
            semantic.SemanticTrace(root, "seed", selector), auto_add=True),
            timeout=worker_timeout("persistent-original"), expect=fixture.CRASH)
        fixture.assert_original_return(original, expected=fixture.CRASH)
        cut = fixture.read_case_json(root, "seed-cut")
        assert cut["selector"] == selector.record() and selector.routes(cut["event"])
        state = semantic._state(cut["snapshot"])
        assert state["inflight"]["kind"] == "create" and state["inflight"]["phase"] == "ARMED" and not state["native"]
        assert set(semantic._native_identities(cut["snapshot"])) == {fixture.signing.DB_NAME, fixture.signing.LOCK_NAME}
        assert cut["snapshot"]["preferences"] == {"default": cut["snapshot"]["original"]["default"],
            "search": [*cut["snapshot"]["original"]["search"], cut["snapshot"]["keychain"]]}
        assert fixture.uncertainty(root, cut["snapshot"])
    else:
        cut, original = semantic.seed(root, seed_name, auto_add=variant == "auto-add-active",
                                      after_effect=keep_profile, context=context)
    fixture.check_case_context(root, context)
    token = cut["sessionToken"]
    evidence = {"schema": "mrk-signing-semantic-case-v1", "case": case.record(),
                "steps": [{"name": "seed", "original": original, "observation": cut}], "negativeEvidence": []}
    model = fixture.PersistentSigningModel(root)
    expected = copy.deepcopy(model.state["original"])
    receipts = {}
    # These are the existing independent fixture-owner edits, not production
    # recovery privileges. Original worker/root custody is checked before them.
    assert fixture._CASE_CUSTODY.get(str(root)) == context[0] == fixture._directory_identity(root)
    if variant in {"foreign-default", "reordered-search", "deleted-search"}:
        foreign = root / "home/foreign.keychain-db"
        foreign.write_bytes(b"unrelated fictional keychain")
        foreign.chmod(0o600)
        model.oracle.record_foreign(foreign, None)
        if variant == "foreign-default":
            model.state["preferences"]["default"] = str(foreign)
            expected["default"] = str(foreign)
        elif variant == "reordered-search":
            model.state["preferences"]["search"] = [expected["search"][1], model.state["keychain"],
                                                   expected["search"][0], str(foreign)]
            expected["search"] = [expected["search"][1], expected["search"][0], str(foreign)]
        else:
            model.state["preferences"]["search"] = []
            expected["search"] = []
        model.save()
    elif variant == "foreign-profile":
        before = fixture.facts(destination)
        foreign = root / "foreign-profile"
        foreign.write_bytes(b"unrelated replacement profile")
        foreign.chmod(0o600)
        foreign.replace(destination)
        assert fixture.facts(destination)["inode"] != before["inode"]
        model.oracle.record_foreign(destination, before)
    elif variant == "profile-inplace-edit":
        before = fixture.facts(destination)
        destination.write_bytes(b"changed in place, not the originally authenticated bytes")
        assert fixture.facts(destination)["inode"] == before["inode"]
    elif variant == "native-unknown-stage":
        stage = Path(model.state["keychain"]).parent / "unknown-transaction-stage"
        stage.write_bytes(b"independently observed fictional native staging")
        stage.chmod(0o600)
        model.oracle.record(stage, "native")
    elif variant == "foreign-native-db":
        database = Path(model.state["keychain"])
        before = fixture.facts(database)
        replacement = root / "foreign-native-database"
        replacement.write_bytes(b"independent foreign replacement keychain")
        replacement.chmod(0o600)
        replacement.replace(database)
        assert fixture.facts(database)["inode"] != before["inode"]
        model.oracle.record_foreign(database, before)
        assert str(database) == model.state["preferences"]["default"] and str(database) in model.state["preferences"]["search"]
    elif variant == "terminal-profile-reappeared":
        assert not destination.exists()
        os.link(root / "retained-fictional-profile", destination)
    elif variant == "terminal-native-reappeared":
        path = Path(model.state["keychain"])
        assert not path.exists()
        path.write_bytes(b"new unexplained native state after completion")
        path.chmod(0o600)
    if variant in fixture.FOCUSED_OWNER_VARIANTS:
        edited = Path(model.state["keychain"]) if variant in {"terminal-native-reappeared", "foreign-native-db"} else destination
        receipts[edited.relative_to(root).as_posix()] = fixture.focused_receipt(root, edited)
        if variant == "terminal-profile-reappeared":
            receipts["retained-fictional-profile"] = fixture.focused_receipt(root, root / "retained-fictional-profile")

    def retain_negative(name, step):
        assert step["observation"].get("refused") is not None or step["observation"].get("resourcesPreserved") is True
        evidence["steps"].append(step)
        evidence["negativeEvidence"].append(semantic._persist_step(parent, identifier, name, step))

    def refusal(name, *, message, preserved, manual="none", terminal=False, preserve_preferences=False):
        fixture.check_case_context(root, context)
        semantic._new_step(root, name)
        original = fixture.run_worker(root, name, lambda: fixture.refusal_case(root, message=message, preserved=preserved,
            manual=manual, terminal=terminal, preserve_preferences=preserve_preferences), timeout=worker_timeout("focused-refusal"))
        fixture.assert_original_return(original)
        value = fixture.read_case_json(root, name)
        assert value["resourcesPreserved"] is True and value["freshAdmission"] == "pending"
        fixture.check_case_context(root, context)
        return {"name": name, "manual": manual, "original": original, "observation": value}

    if variant in {"foreign-default", "reordered-search", "deleted-search", "foreign-profile", "auto-add-active", "borrowed-profile"}:
        status = catalog.RECOVERED if variant in {"auto-add-active", "borrowed-profile"} else catalog.CONFLICT
        evidence["steps"].append(semantic.recovery_step(root, "focused-main", token=token, manual="none", expected=status,
            expected_preferences=expected, context=context, final=True))
    elif variant in {"native-unknown-stage", "auto-add-ambiguous-create"}:
        negative = semantic.recovery_step(root, "focused-refusal", token=token, manual="none", expected=catalog.REFUSED,
                                           context=context, final=False)
        retain_negative("negative", negative)
        evidence["steps"].append(semantic.recovery_step(root, "focused-resolution", token=token, manual="resolve",
            expected=catalog.CONFLICT if variant == "native-unknown-stage" else catalog.RECOVERED, context=context, final=True))
    elif variant == "foreign-native-db":
        preserved = {str(database.relative_to(root)): fixture.facts(database)}
        for mode, message in (("none", "native transaction identity is unknown"),
                              ("resolve", "owner cannot identify an intervening replacement/edit")):
            retain_negative("negative-" + mode, refusal("focused-" + mode, message=message, preserved=preserved,
                                                        manual=mode, preserve_preferences=True))
    else:
        manual, terminal, preserved = "none", variant.startswith("terminal-"), {}
        if variant == "profile-inplace-edit":
            message = "owned profile bytes changed"
            preserved[str(destination.relative_to(root))] = fixture.facts(destination)
        elif variant == "terminal-profile-reappeared":
            message = "previously cleaned profile resource reappeared"
            preserved[str(destination.relative_to(root))] = fixture.facts(destination)
        elif variant == "terminal-native-reappeared":
            message = "terminal session has new native resources/references"
            path = Path(model.state["keychain"])
            preserved[str(path.relative_to(root))] = fixture.facts(path)
        else:
            assert variant in {"manual-wrong", "manual-eof", "manual-cancel"}
            manual = variant.removeprefix("manual-")
            message = "manual recheck cancelled or incorrect"
            preserved = fixture.ResourceOracle(root).owned_remaining()
        retain_negative("negative", refusal("focused-refusal", message=message, preserved=preserved,
                                             manual=manual, terminal=terminal))
        if variant.startswith("manual-"):
            evidence["steps"].append(semantic.recovery_step(root, "focused-resolution", token=token, manual="resolve",
                                                           expected=catalog.RECOVERED, context=context, final=True))
    if variant in fixture.FOCUSED_OWNER_VARIANTS:
        fixture.check_case_context(root, context)
        plan = fixture.focused_owner_plan(root, variant, receipts)
        # The enhanced fixed child performs full postconditions. This return is
        # the actual immediate owner continuation, not JSON finality authority.
        final = fixture.settle_focused_fixture(root, plan, report=True)
        expected = final["preferences"]
        evidence["steps"].append({"name": "focused-fixture-owner", "original": final["original"],
                                   "observation": final["observation"]})
    fixture.check_case_context(root, context)
    assert str(root) not in fixture._CASE_RECOVERY_DEBT
    evidence_name = semantic._persist_step(parent, identifier, "complete", evidence)
    fixture.remove_case(root)
    assert not root.exists() and str(root) not in fixture._CASE_CUSTODY
    fixture.check_phase_context(context)
    return {"caseId": identifier, "status": "semantic-subset-case", "evidence": evidence_name,
            "caseRemoved": True, "originalWorkersSettled": True}
