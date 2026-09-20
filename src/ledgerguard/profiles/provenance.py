"""Provenance profile: instrument runs and research data custody.

This is the second domain profile, and it exists to test a claim rather than
to serve a second market.  The claim is that the integrity machinery is
domain-independent: that ``schema``, ``canonical``, ``merkle``, ``commitment``,
``backends`` and ``verifier`` contain nothing specific to accounting.  A single
profile cannot establish that, because any abstraction looks general when it
has exactly one client.

The profile is deliberately chosen to stress parts of the schema layer the
accounting profile never touches:

*   ``DATETIME`` fields, and therefore the UTC normalisation path.  An
    instrument in one timezone and an analysis pipeline in another must not
    produce different digests for the same recorded instant.
*   ``BOOLEAN`` fields.
*   Domain invariants of an entirely different shape.  Accounting checks that
    debits equal credits; here the rules are that events within a run are
    chronologically ordered, that a measurement is preceded by a calibration,
    and that any referenced data artefact is named by a well-formed digest.

The record is one *event* in an instrument run: a sample loaded, a calibration
performed, a measurement taken, a file written.  Events sharing a run
identifier form a run, and it is the run that must be internally consistent.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from itertools import pairwise
from typing import Any, Iterable, Mapping, Sequence

from ..schema import FieldSpec, FieldType, RecordSchema

#: Event kinds a run may record.
RUN_START = "run_start"
SAMPLE_LOADED = "sample_loaded"
CALIBRATION = "calibration"
MEASUREMENT = "measurement"
ARTIFACT_WRITTEN = "artifact_written"
RUN_END = "run_end"

EVENT_TYPES = frozenset(
    {RUN_START, SAMPLE_LOADED, CALIBRATION, MEASUREMENT, ARTIFACT_WRITTEN, RUN_END}
)

#: Event kinds whose validity depends on a prior calibration in the same run.
REQUIRES_CALIBRATION = frozenset({MEASUREMENT, ARTIFACT_WRITTEN})

_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")

#: Schema for a single instrument-run event.
#:
#: ``event_seq`` is the globally monotonic sequence carrying the interval
#: commitment, exactly as ``line_seq`` does in the accounting profile.  That
#: the two profiles differ in every other field and share only this one is the
#: point: the commitment layer needs a sequence and nothing else.
INSTRUMENT_EVENT_V1 = RecordSchema(
    schema_id="provenance.instrument_event",
    version=1,
    sequence_field="event_seq",
    fields=(
        FieldSpec("event_seq", FieldType.INTEGER),
        FieldSpec("run_id", FieldType.STRING),
        FieldSpec("event_type", FieldType.STRING),
        FieldSpec("recorded_at", FieldType.DATETIME),
        FieldSpec("instrument_id", FieldType.STRING),
        FieldSpec("operator", FieldType.STRING),
        FieldSpec("sample_id", FieldType.STRING, nullable=True),
        FieldSpec("artifact_digest", FieldType.STRING, nullable=True),
        FieldSpec("parameters", FieldType.STRING, nullable=True),
        FieldSpec("is_automated", FieldType.BOOLEAN),
    ),
)


class ProvenanceError(ValueError):
    """A run violates an invariant of the provenance model."""


def validate_event(record: Mapping[str, Any]) -> None:
    """Check the invariants that hold for a single event.

    Raises:
        ProvenanceError: the event type is unknown, an artefact event names no
            artefact, or an artefact digest is malformed.
    """
    event_type = record["event_type"]
    if event_type not in EVENT_TYPES:
        raise ProvenanceError(
            f"event {record.get('event_seq')}: unknown event type {event_type!r}"
        )

    digest = record.get("artifact_digest")
    if event_type == ARTIFACT_WRITTEN and not digest:
        raise ProvenanceError(
            f"event {record.get('event_seq')}: an artefact event must name the "
            "artefact it produced"
        )
    if digest is not None and not _SHA256_HEX.match(digest):
        raise ProvenanceError(
            f"event {record.get('event_seq')}: {digest!r} is not a lowercase "
            "hex SHA-256 digest"
        )

    if event_type in (SAMPLE_LOADED, MEASUREMENT) and not record.get("sample_id"):
        raise ProvenanceError(
            f"event {record.get('event_seq')}: {event_type} must name a sample"
        )


def validate_run_ordering(events: Sequence[Mapping[str, Any]]) -> None:
    """Check that time and sequence agree within each run.

    An event with a later sequence number must not carry an earlier timestamp.
    A backdated event is the provenance analogue of a cut-off manipulation:
    the record exists, is well-formed, and claims to have happened before
    something that was already recorded.

    Raises:
        ProvenanceError: some run's timestamps contradict its sequence order.
    """
    runs: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        validate_event(event)
        runs[event["run_id"]].append(event)

    for run_id, run_events in sorted(runs.items()):
        ordered = sorted(run_events, key=lambda e: int(e["event_seq"]))
        for earlier, later in pairwise(ordered):
            if _instant(later) < _instant(earlier):
                raise ProvenanceError(
                    f"run {run_id}: event {later['event_seq']} is timestamped "
                    f"before event {earlier['event_seq']}"
                )


def validate_calibration_order(events: Sequence[Mapping[str, Any]]) -> None:
    """Check that measurements in a run follow a calibration.

    A measurement recorded before any calibration is not evidence of anything,
    so a run that reports one is either mis-sequenced or has had its
    calibration record removed -- which is precisely the kind of deletion the
    interval commitment is there to catch.

    Raises:
        ProvenanceError: a run measures before it calibrates.
    """
    runs: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        runs[event["run_id"]].append(event)

    for run_id, run_events in sorted(runs.items()):
        ordered = sorted(run_events, key=lambda e: int(e["event_seq"]))
        calibrated = False
        for event in ordered:
            if event["event_type"] == CALIBRATION:
                calibrated = True
            elif event["event_type"] in REQUIRES_CALIBRATION and not calibrated:
                raise ProvenanceError(
                    f"run {run_id}: event {event['event_seq']} "
                    f"({event['event_type']}) precedes any calibration"
                )


def validate_run(events: Sequence[Mapping[str, Any]]) -> None:
    """Run every provenance invariant over a set of events."""
    validate_run_ordering(events)
    validate_calibration_order(events)


def _instant(event: Mapping[str, Any]) -> datetime:
    value = event["recorded_at"]
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def group_by_run(
    events: Iterable[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    """Group events by run identifier, preserving sequence order."""
    runs: dict[str, list[Mapping[str, Any]]] = {}
    for event in sorted(events, key=lambda e: int(e["event_seq"])):
        runs.setdefault(event["run_id"], []).append(event)
    return runs
