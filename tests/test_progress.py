from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from nordis_smb_inspector.core.progress import (
    ActiveWork,
    ProgressTracker,
    ScanPhase,
    StaleProgressUpdate,
)


class ProgressTrackerTests(unittest.TestCase):
    def test_phase_percent_and_counter_updates(self) -> None:
        tracker = ProgressTracker()
        tracker.set_phase(ScanPhase.CONNECTIVITY, total=4, overall_percent=10)
        tracker.update_progress(2, expected_phase=ScanPhase.CONNECTIVITY)
        snapshot = tracker.increment("targets_open")

        self.assertEqual(snapshot.phase, ScanPhase.CONNECTIVITY)
        self.assertEqual(snapshot.phase_percent, 50.0)
        self.assertEqual(snapshot.counters["targets_open"], 1)

    def test_listener_receives_snapshots_until_unsubscribed(self) -> None:
        tracker = ProgressTracker()
        sequences: list[int] = []
        unsubscribe = tracker.subscribe(lambda snapshot: sequences.append(snapshot.sequence))

        tracker.increment("files")
        unsubscribe()
        unsubscribe()
        tracker.increment("files")

        self.assertEqual(sequences, [1])

    def test_active_worker_ids_must_be_unique(self) -> None:
        tracker = ProgressTracker()
        work = (
            ActiveWork(worker_id="one", action="reading", target="10.0.0.1"),
            ActiveWork(worker_id="one", action="reading", target="10.0.0.2"),
        )

        with self.assertRaises(ValueError):
            tracker.set_active_work(work)

    def test_counter_increments_are_atomic(self) -> None:
        tracker = ProgressTracker()

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(tracker.increment, "files") for _ in range(500)]
            for future in futures:
                future.result()

        self.assertEqual(tracker.snapshot.counters["files"], 500)

    def test_listener_failure_is_isolated_and_delivery_stays_ordered(self) -> None:
        tracker = ProgressTracker()
        received: list[int] = []

        def fail(_snapshot: object) -> None:
            raise RuntimeError("disconnected UI")

        tracker.subscribe(fail)
        tracker.subscribe(lambda snapshot: received.append(snapshot.sequence))

        tracker.increment("files")
        tracker.increment("files")

        self.assertEqual(received, [1, 2])

    def test_stale_phase_update_is_rejected(self) -> None:
        tracker = ProgressTracker()
        tracker.set_phase(ScanPhase.CONNECTIVITY, total=10)
        tracker.set_phase(ScanPhase.AUTHENTICATION, total=2)

        with self.assertRaises(StaleProgressUpdate):
            tracker.update_progress(
                5,
                total=10,
                expected_phase=ScanPhase.CONNECTIVITY,
            )

        self.assertEqual(tracker.snapshot.phase, ScanPhase.AUTHENTICATION)
        self.assertEqual(tracker.snapshot.phase_completed, 0)

    def test_active_work_is_copied_to_an_immutable_tuple(self) -> None:
        tracker = ProgressTracker()
        work = [ActiveWork(worker_id="one", action="reading")]

        snapshot = tracker.set_active_work(work)
        work.clear()

        self.assertEqual(len(snapshot.active_work), 1)


if __name__ == "__main__":
    unittest.main()
