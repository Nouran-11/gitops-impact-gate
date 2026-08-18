from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from impactgate.controller.actions import Action, Diagnosis, classify_failure
from impactgate.controller.policy import default_policy, policy_from_crd
from impactgate.controller.watcher import (
    Debouncer,
    NullClusterClient,
    compress_logs,
    extract_waiting_reason,
    handle_failure,
    is_managed,
)


def _pod(*, reason: str, managed: bool = True, oom: bool = False) -> dict[str, object]:
    waiting = {"reason": reason} if not oom else {}
    terminated = {"reason": "OOMKilled"} if oom else {}
    return {
        "metadata": {
            "name": "checkout-0",
            "namespace": "demo",
            "labels": {"impactgate.io/managed": "true" if managed else "false"},
        },
        "status": {
            "containerStatuses": [
                {
                    "name": "app",
                    "state": {"waiting": waiting} if waiting else {"running": {}},
                    "lastState": {"terminated": terminated},
                }
            ]
        },
    }


def test_classify_image_pull_is_rollback() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="storefront",
        reason="ImagePullBackOff",
        compressed_logs="",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.ROLLBACK


def test_classify_app_bug_is_escalate() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="payments",
        reason="CrashLoopBackOff",
        compressed_logs="Traceback (most recent call last):\nValueError: boom",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.ESCALATE


def test_classify_oom_is_bump_memory() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="storefront",
        reason="CrashLoopBackOff",
        compressed_logs="lastState: OOMKilled",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.BUMP_MEMORY


def test_debounce_requires_threshold() -> None:
    debouncer = Debouncer(threshold=3, window=timedelta(minutes=5))
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert debouncer.record("demo/app", start) is False
    assert debouncer.record("demo/app", start + timedelta(minutes=1)) is False
    assert debouncer.record("demo/app", start + timedelta(minutes=2)) is True


def test_compress_logs_collapses_repeats() -> None:
    raw = "ready\nerror\nerror\nerror\ndone\n"
    compressed = compress_logs(raw)
    assert compressed.count("error") == 1
    assert "repeated 2 more times" in compressed


def test_extract_waiting_reason() -> None:
    assert extract_waiting_reason(_pod(reason="CrashLoopBackOff")) == "CrashLoopBackOff"
    assert extract_waiting_reason(_pod(reason="Running", oom=True)) == "OOMKilled"


def test_unmanaged_pods_are_skipped() -> None:
    assert is_managed(_pod(reason="CrashLoopBackOff", managed=False)) is False


def test_dry_run_logs_intended_action(caplog: logging.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="impactgate.controller")
    debouncer = Debouncer(threshold=1)
    action = handle_failure(
        _pod(reason="ImagePullBackOff"),
        reason="ImagePullBackOff",
        client=NullClusterClient(),
        debouncer=debouncer,
        policy=default_policy(),
    )
    assert action == Action.ROLLBACK
    assert any("dry-run: would rollback" in rec.message for rec in caplog.records)


def test_policy_from_crd_and_default() -> None:
    policy = policy_from_crd(
        {
            "mode": "enforce",
            "minConfidence": 0.9,
            "allowedActions": ["rollback", "restart"],
            "maxActionsPerHour": 2,
        }
    )
    assert policy.mode == "enforce"
    assert Action.ROLLBACK in policy.allowed_actions
    assert default_policy().dry_run is True
    assert default_policy().allowed_actions == []
