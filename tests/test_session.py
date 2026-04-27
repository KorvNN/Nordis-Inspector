from __future__ import annotations

import re
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

from nordis_smb_inspector.core.progress import ScanPhase
from nordis_smb_inspector.core.session import (
    CapacityReached,
    InvalidScanTransition,
    ResultCollection,
    ScanAlreadyRunning,
    ScanCancelled,
    ScanSessionManager,
    ScanStatus,
    ScanToken,
    SessionLimits,
    StaleScanUpdate,
    TerminalReason,
)


class SessionLimitsTests(unittest.TestCase):
    def test_limits_are_finite_positive_and_page_defaults_fit(self) -> None:
        for changes in (
            {"max_inventory_items": 0},
            {"max_findings": -1},
            {"default_page_size": 0},
            {"max_page_size": 0},
            {"default_page_size": 11, "max_page_size": 10},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                SessionLimits(**changes)


class ScanSessionManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = ScanSessionManager(
            SessionLimits(
                max_inventory_items=100,
                max_findings=100,
                default_page_size=2,
                max_page_size=4,
            )
        )

    def test_initial_snapshot_is_immutable_idle_state(self) -> None:
        state = self.manager.snapshot

        self.assertEqual(state.status, ScanStatus.IDLE)
        self.assertEqual(state.generation, 0)
        self.assertIsNone(state.scan_id)
        self.assertFalse(state.active)
        self.assertFalse(state.terminal)
        with self.assertRaises(FrozenInstanceError):
            state.status = ScanStatus.RUNNING  # type: ignore[misc]

    def test_begin_uses_uuid4_and_allows_only_one_active_scan(self) -> None:
        handle = self.manager.begin_scan()

        self.assertRegex(
            handle.token.scan_id,
            re.compile(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
        )
        self.assertEqual(handle.token.generation, 1)
        self.assertEqual(self.manager.snapshot.status, ScanStatus.RUNNING)
        with self.assertRaises(ScanAlreadyRunning):
            self.manager.begin_scan()

    def test_progress_tracker_is_mirrored_into_session_snapshot(self) -> None:
        handle = self.manager.begin_scan()

        handle.progress.set_phase(ScanPhase.CONNECTIVITY, total=4)
        handle.progress.update_progress(2, expected_phase=ScanPhase.CONNECTIVITY)
        handle.progress.increment("open_ports")

        progress = self.manager.snapshot.progress
        assert progress is not None
        self.assertEqual(progress.phase, ScanPhase.CONNECTIVITY)
        self.assertEqual(progress.phase_percent, 50.0)
        self.assertEqual(progress.counters["open_ports"], 1)

    def test_cancel_signal_is_cooperative_and_lifecycle_is_explicit(self) -> None:
        handle = self.manager.begin_scan()
        self.assertFalse(handle.cancellation.requested)

        cancelling = self.manager.request_cancel(handle.token)
        repeated = self.manager.request_cancel(handle.token)

        self.assertEqual(cancelling.status, ScanStatus.CANCELLING)
        self.assertEqual(repeated.status, ScanStatus.CANCELLING)
        self.assertTrue(handle.cancellation.requested)
        self.assertTrue(handle.cancellation.wait(0))
        with self.assertRaises(ScanCancelled):
            handle.cancellation.raise_if_requested()

        cancelled = self.manager.mark_cancelled(handle.token)
        self.assertEqual(cancelled.status, ScanStatus.CANCELLED)
        self.assertEqual(cancelled.terminal_reason, TerminalReason.CANCELLED)
        self.assertEqual(cancelled.progress.phase, ScanPhase.CANCELLED)

    def test_complete_during_cancellation_acknowledges_cancel(self) -> None:
        handle = self.manager.begin_scan()
        self.manager.request_cancel(handle.token)

        state = self.manager.complete(handle.token)

        self.assertEqual(state.status, ScanStatus.CANCELLED)
        self.assertEqual(state.terminal_reason, TerminalReason.CANCELLED)

    def test_results_remain_after_completion_and_clear_only_on_new_begin(self) -> None:
        first = self.manager.begin_scan()
        self.manager.add_inventory(first.token, "visible-file")
        self.manager.add_finding(first.token, "matching-line")
        self.manager.complete(first.token)

        self.assertEqual(self.manager.inventory_page(first.token).items, ("visible-file",))
        self.assertEqual(self.manager.findings_page(first.token).items, ("matching-line",))

        second = self.manager.begin_scan()
        self.assertEqual(second.token.generation, first.token.generation + 1)
        self.assertNotEqual(second.token.scan_id, first.token.scan_id)
        self.assertEqual(self.manager.inventory_page(second.token).total_items, 0)
        self.assertEqual(self.manager.findings_page(second.token).total_items, 0)
        with self.assertRaises(StaleScanUpdate):
            self.manager.inventory_page(first.token)

    def test_inventory_upsert_replaces_one_logical_row_without_count_growth(self) -> None:
        handle = self.manager.begin_scan()

        first_count = self.manager.upsert_inventory(
            handle.token,
            ("target", "share", "file.txt", "file"),
            {"status": "file_readable"},
        )
        replacement_count = self.manager.upsert_inventory(
            handle.token,
            ("target", "share", "file.txt", "file"),
            {"status": "read_error"},
        )
        second_count = self.manager.upsert_inventory(
            handle.token,
            ("target", "share", "other.txt", "file"),
            {"status": "file_readable"},
        )

        page = self.manager.inventory_page(handle.token)
        self.assertEqual((first_count, replacement_count, second_count), (1, 1, 2))
        self.assertEqual(page.total_items, 2)
        self.assertEqual(page.items[0], {"status": "read_error"})
        self.assertEqual(self.manager.snapshot.inventory_count, 2)

    def test_stale_id_or_generation_cannot_mutate_current_scan(self) -> None:
        first = self.manager.begin_scan()
        self.manager.complete(first.token)
        second = self.manager.begin_scan()
        wrong_id = ScanToken(first.token.scan_id, second.token.generation)
        wrong_generation = ScanToken(second.token.scan_id, first.token.generation)

        for token in (first.token, wrong_id, wrong_generation):
            with self.subTest(token=token), self.assertRaises(StaleScanUpdate):
                self.manager.add_inventory(token, "must-not-be-added")

        self.assertEqual(self.manager.snapshot.inventory_count, 0)

    def test_stale_progress_tracker_cannot_update_new_generation(self) -> None:
        first = self.manager.begin_scan()
        self.manager.complete(first.token)
        second = self.manager.begin_scan()
        before = self.manager.snapshot.progress

        first.progress.increment("stale_worker_counter")

        self.assertIs(self.manager.snapshot.progress, before)
        self.assertEqual(self.manager.snapshot.token, second.token)

    def test_pagination_is_configurable_bounded_and_stable(self) -> None:
        handle = self.manager.begin_scan()
        for number in range(5):
            self.manager.add_inventory(handle.token, f"file-{number}")

        first = self.manager.inventory_page(handle.token)
        second = self.manager.inventory_page(handle.token, page=2)
        last = self.manager.inventory_page(handle.token, page=3)

        self.assertEqual(first.items, ("file-0", "file-1"))
        self.assertEqual(first.total_items, 5)
        self.assertEqual(first.total_pages, 3)
        self.assertFalse(first.has_previous)
        self.assertTrue(first.has_next)
        self.assertEqual(second.items, ("file-2", "file-3"))
        self.assertEqual(last.items, ("file-4",))
        self.assertFalse(last.has_next)

        for page, size in ((0, None), (1, 0), (1, 5)):
            with self.subTest(page=page, size=size), self.assertRaises(ValueError):
                self.manager.inventory_page(handle.token, page=page, page_size=size)

    def test_inventory_capacity_is_visible_terminal_partial_result(self) -> None:
        manager = ScanSessionManager(
            SessionLimits(
                max_inventory_items=1,
                max_findings=2,
                default_page_size=1,
                max_page_size=2,
            )
        )
        handle = manager.begin_scan()
        manager.add_inventory(handle.token, "kept-item")

        with self.assertRaises(CapacityReached) as raised:
            manager.add_inventory(handle.token, "explicitly-rejected-item")

        self.assertEqual(raised.exception.collection, ResultCollection.INVENTORY)
        self.assertEqual(raised.exception.limit, 1)
        state = manager.snapshot
        self.assertEqual(state.status, ScanStatus.FAILED)
        self.assertEqual(state.terminal_reason, TerminalReason.CAPACITY_REACHED)
        self.assertEqual(state.capacity_collection, ResultCollection.INVENTORY)
        self.assertTrue(state.partial)
        self.assertTrue(handle.cancellation.requested)
        self.assertEqual(manager.inventory_page(handle.token).items, ("kept-item",))
        with self.assertRaises(InvalidScanTransition):
            manager.add_inventory(handle.token, "after-terminal")

    def test_finding_capacity_identifies_the_correct_collection(self) -> None:
        manager = ScanSessionManager(
            SessionLimits(
                max_inventory_items=2,
                max_findings=1,
                default_page_size=1,
                max_page_size=2,
            )
        )
        handle = manager.begin_scan()
        manager.add_finding(handle.token, "one")

        with self.assertRaises(CapacityReached) as raised:
            manager.add_finding(handle.token, "two")

        self.assertEqual(raised.exception.collection, ResultCollection.FINDINGS)
        self.assertEqual(manager.snapshot.finding_count, 1)

    def test_concurrent_appends_are_thread_safe(self) -> None:
        manager = ScanSessionManager(
            SessionLimits(
                max_inventory_items=1_000,
                max_findings=1_000,
                default_page_size=100,
                max_page_size=1_000,
            )
        )
        handle = manager.begin_scan()

        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [
                executor.submit(manager.add_inventory, handle.token, number)
                for number in range(1_000)
            ]
            for future in futures:
                future.result()

        self.assertEqual(manager.snapshot.inventory_count, 1_000)
        page = manager.inventory_page(handle.token, page_size=1_000)
        self.assertEqual(len(page.items), 1_000)
        self.assertEqual(set(page.items), set(range(1_000)))

    def test_failed_scan_retains_partial_records_without_error_text(self) -> None:
        handle = self.manager.begin_scan()
        self.manager.add_finding(handle.token, "secret-value")

        state = self.manager.fail(handle.token)

        self.assertEqual(state.status, ScanStatus.FAILED)
        self.assertEqual(state.terminal_reason, TerminalReason.WORKER_FAILED)
        self.assertTrue(state.partial)
        self.assertEqual(self.manager.findings_page(handle.token).items, ("secret-value",))

    def test_safe_representations_never_include_result_contents(self) -> None:
        handle = self.manager.begin_scan()
        secret = "database_password = do-not-print-this"
        self.manager.add_inventory(handle.token, secret)
        self.manager.add_finding(handle.token, secret)
        page = self.manager.findings_page(handle.token)

        for value in (self.manager, self.manager.snapshot, handle, page):
            with self.subTest(type=type(value).__name__):
                self.assertNotIn(secret, repr(value))

    def test_terminal_transitions_are_rejected(self) -> None:
        handle = self.manager.begin_scan()
        self.manager.complete(handle.token)

        with self.assertRaises(InvalidScanTransition):
            self.manager.complete(handle.token)
        with self.assertRaises(InvalidScanTransition):
            self.manager.request_cancel(handle.token)


if __name__ == "__main__":
    unittest.main()
