"""Actual restart History originals, zero Store/Git calls and no grant/repair."""
import unittest
import test_local_execution_review as execution
import test_local_candidate_inputs as candidate
import test_local_release_history as history

class ReconcileReviewTests(unittest.TestCase):
    setUp=execution.ExecutionReviewTests.setUp
    tearDown=execution.ExecutionReviewTests.tearDown
    run_original=execution.ExecutionReviewTests.run_original
    journal=execution.ExecutionReviewTests.journal
    pending=execution.ExecutionReviewTests.pending
    ready=execution.ExecutionReviewTests.ready
    prepared=execution.ExecutionReviewTests.prepared
    request=execution.ExecutionReviewTests.request
    completed=execution.ExecutionReviewTests.completed
    def originals(self):return {p:(p.stat().st_ino,p.read_bytes()) for p in self.base.rglob('*') if p.is_file()}
    def test_restart_current_pending_and_known_suffixes_supply_only_prepared_data(self):
        for phase in (None,'settled-success','settled-failure','reconciliation-required'):
            if phase is not None:self.tearDown();self.setUp()
            path,directory,intent=self.completed(phase=phase);before=self.originals()
            terminal,events,engine=self.run_original('review-reconcile')
            self.assertEqual(terminal['outcome'],'complete',engine.primary)
            self.assertEqual([r[0] for r in events],['lease-ready','history-head']);self.assertEqual(terminal['lifetime']['commands'],0)
            result=terminal['result'];self.assertEqual(set(result),{'schemaVersion','scope','enrolled','headSequence','history','limitations','preparedIntent'})
            p=result['preparedIntent'];self.assertEqual(len(p),13);self.assertEqual(p['intentSha256'],intent['integrity']['sha256'])
            self.assertEqual(p['observation'],'current-prepared-files-only');self.assertEqual(p['priorPrepareFinality'],'not-established')
            self.assertEqual(before,self.originals());self.assertTrue(engine.service.closed())
            ordinary,_,_=self.run_original('review-prepared');self.assertEqual(ordinary['outcome'],'refused')
    def test_early_prepare_or_superseded_operation_cannot_supply_reconcile_selection(self):
        self.prepared();t,_,_=self.run_original('review-reconcile');self.assertEqual(t['outcome'],'refused')
        self.tearDown();self.setUp();self.completed()
        j=self.journal()
        try:j._append(expected_head=j.head(),operation_id='66666666-6666-4666-8666-666666666666',phase='inputs-pending',payload=candidate.PENDING)
        finally:j.close()
        t,_,_=self.run_original('review-reconcile');self.assertEqual(t['outcome'],'refused')
    def test_crossed_pending_assignment_and_changed_prepared_original_refuse(self):
        self.completed(pending={'assignmentRevision':999})
        t,_,_=self.run_original('review-reconcile');self.assertEqual(t['outcome'],'refused')
        self.tearDown();self.setUp();_,directory,_=self.completed(phase=None)
        (directory/'operation-intent.json').write_bytes(b'changed original')
        t,_,engine=self.run_original('review-reconcile');self.assertEqual(t['outcome'],'refused');self.assertTrue(engine.service.closed())
