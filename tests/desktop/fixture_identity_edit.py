"""Original identity transaction for task-owned source/build fixtures only."""
import sys

from mobile_release import init_transaction as tx, project_identity_edit as edit
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease


def apply_new_identity(root, selection, desired):
    v = root.stat()
    guard = DefaultCancellation(ValidationError, "fixture identity cleanup failed")
    lease = InitRootLease(root, cancellation=guard, profile=tx.TypedEditProfile.PROJECT_IDENTITY,
        registered_identity={"device": v.st_dev, "inode": v.st_ino, "mode": v.st_mode, "uid": v.st_uid, "gid": v.st_gid})
    scope = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
    try:
        with scope:
            guard.install(); guard.activate(); lease.acquire()
            checkout = edit.capture_project_identity_edit(lease, selection)
            if checkout.view["state"] != "supported":
                raise AssertionError(checkout.view)
            plan = edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                                                      desired_identity=desired, intent="new-application")
            outcome = edit.apply_project_identity_edit(lease, plan)
            if (outcome.effect, outcome.journal, outcome.resources, outcome.reason) != ("committed", "clean", "settled", "none"):
                raise AssertionError(outcome)
    finally:
        scope.__exit__(*sys.exc_info())
    if not lease.closed or guard.handler_state != "RESTORED" or guard.lifetime_ledger.fatal:
        raise AssertionError("original identity fixture resources did not settle")
    return outcome
