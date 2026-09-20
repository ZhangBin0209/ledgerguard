"""Provenance profile tests.

Two jobs. First, the domain rules: chronological ordering, calibration before
measurement, well-formed artefact digests. Second, and more important for the
architecture, that the entire pipeline -- canonicalisation, Merkle, commitment,
anchoring, verification -- works on this profile with no change whatsoever to
the layers below. That is the claim the second profile exists to test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ledgerguard import (
    BatchBuilder,
    MemoryBackend,
    Verdict,
    Verifier,
    record_digest,
    synth,
)
from ledgerguard.profiles import get_profile, profile_names
from ledgerguard.profiles.provenance import (
    ARTIFACT_WRITTEN,
    CALIBRATION,
    INSTRUMENT_EVENT_V1,
    MEASUREMENT,
    RUN_START,
    ProvenanceError,
    group_by_run,
    validate_calibration_order,
    validate_event,
    validate_run,
    validate_run_ordering,
)

SCHEMA = INSTRUMENT_EVENT_V1
T0 = datetime(2026, 2, 3, 8, 0, tzinfo=timezone.utc)


def ev(seq, kind=MEASUREMENT, run="RUN-1", minutes=0, sample="S-1",
       digest=None, params=None):
    return {
        "event_seq": seq, "run_id": run, "event_type": kind,
        "recorded_at": T0 + timedelta(minutes=minutes),
        "instrument_id": "LC-MS-01", "operator": "m.torres",
        "sample_id": sample, "artifact_digest": digest,
        "parameters": params, "is_automated": False,
    }


# -- registry ---------------------------------------------------------------

def test_both_profiles_are_registered():
    assert profile_names() == ("accounting", "provenance")
    assert get_profile("provenance") is SCHEMA


def test_unknown_profile_lists_the_alternatives():
    with pytest.raises(KeyError, match="accounting, provenance"):
        get_profile("nope")


def test_profiles_share_only_a_sequence_field():
    """The commitment layer needs a sequence and nothing else."""
    accounting = get_profile("accounting")
    shared = set(accounting.field_names) & set(SCHEMA.field_names)
    assert shared == set()
    assert accounting.sequence_field and SCHEMA.sequence_field


# -- domain rules -----------------------------------------------------------

def test_valid_run_passes():
    validate_run([
        ev(1, RUN_START, minutes=0, sample=None),
        ev(2, CALIBRATION, minutes=1, sample=None),
        ev(3, MEASUREMENT, minutes=2),
    ])


def test_measurement_before_calibration_is_rejected():
    with pytest.raises(ProvenanceError, match="precedes any calibration"):
        validate_calibration_order([
            ev(1, RUN_START, minutes=0, sample=None),
            ev(2, MEASUREMENT, minutes=1),
            ev(3, CALIBRATION, minutes=2, sample=None),
        ])


def test_backdated_event_is_rejected():
    """The provenance analogue of a cut-off manipulation."""
    with pytest.raises(ProvenanceError, match="timestamped before"):
        validate_run_ordering([ev(1, CALIBRATION, minutes=10, sample=None),
                               ev(2, MEASUREMENT, minutes=5)])


def test_runs_are_ordered_independently():
    validate_run_ordering([
        ev(1, CALIBRATION, run="A", minutes=10, sample=None),
        ev(2, CALIBRATION, run="B", minutes=1, sample=None),
        ev(3, MEASUREMENT, run="A", minutes=20),
        ev(4, MEASUREMENT, run="B", minutes=30),
    ])


def test_unknown_event_type_is_rejected():
    with pytest.raises(ProvenanceError, match="unknown event type"):
        validate_event(ev(1, "deleted_the_evidence"))


def test_artefact_event_must_name_an_artefact():
    with pytest.raises(ProvenanceError, match="must name the artefact"):
        validate_event(ev(1, ARTIFACT_WRITTEN, sample=None))


def test_malformed_digest_is_rejected():
    with pytest.raises(ProvenanceError, match="hex SHA-256"):
        validate_event(ev(1, ARTIFACT_WRITTEN, digest="not-a-digest"))


def test_uppercase_digest_is_rejected():
    """Case matters: two spellings of one digest would hash differently."""
    with pytest.raises(ProvenanceError):
        validate_event(ev(1, ARTIFACT_WRITTEN, digest="A" * 64))


def test_measurement_must_name_a_sample():
    with pytest.raises(ProvenanceError, match="must name a sample"):
        validate_event(ev(1, MEASUREMENT, sample=None))


def test_group_by_run_preserves_sequence_order():
    grouped = group_by_run([ev(3, run="A"), ev(1, run="A"), ev(2, run="B")])
    assert [e["event_seq"] for e in grouped["A"]] == [1, 3]


# -- the datetime path the accounting profile never exercises ---------------

def test_timezone_offsets_normalise_to_the_same_digest():
    utc = ev(1)
    shifted = dict(utc)
    shifted["recorded_at"] = utc["recorded_at"].astimezone(
        timezone(timedelta(hours=9)))
    assert utc["recorded_at"].isoformat() != shifted["recorded_at"].isoformat()
    assert record_digest(utc, SCHEMA) == record_digest(shifted, SCHEMA)


def test_boolean_field_affects_the_digest():
    base = ev(1)
    flipped = dict(base, is_automated=True)
    assert record_digest(base, SCHEMA) != record_digest(flipped, SCHEMA)


# -- the whole pipeline, unchanged ------------------------------------------

def test_generated_provenance_ledger_is_valid():
    ledger = synth.generate_provenance(runs=40, seed=1)
    validate_run(ledger.records)
    assert ledger.schema is SCHEMA
    assert list(ledger.sequences) == sorted(ledger.sequences)


def test_generation_is_reproducible():
    a = synth.generate_provenance(runs=20, seed=5)
    b = synth.generate_provenance(runs=20, seed=5)
    assert [record_digest(r, SCHEMA) for r in a] == \
           [record_digest(r, SCHEMA) for r in b]


def test_anchor_and_verify_on_the_second_profile():
    """The core layers are given a schema, not a domain. Nothing else changes."""
    ledger = synth.generate_provenance(runs=40, seed=2, batch_size=50)
    backend = MemoryBackend()
    witnesses = {}
    for i, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{i}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()

    report = Verifier(backend, SCHEMA).verify_ledger(ledger.records, witnesses)
    assert report.intact


def test_tampering_is_detected_on_the_second_profile():
    ledger = synth.generate_provenance(runs=40, seed=3, batch_size=50)
    backend = MemoryBackend()
    witnesses = {}
    for i, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{i}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()

    # Delete a calibration event: the run now measures without calibrating,
    # and the interval commitment catches the removal.
    victim = next(r for r in ledger.records if r["event_type"] == CALIBRATION)
    survivors = [r for r in ledger.records if r is not victim]

    report = Verifier(backend, SCHEMA).verify_ledger(survivors, witnesses)
    assert not report.intact
    assert report.count(Verdict.DELETED) == 1

    with pytest.raises(ProvenanceError, match="precedes any calibration"):
        validate_calibration_order(survivors)


def test_evm_backend_works_on_the_second_profile():
    pytest.importorskip("web3")
    pytest.importorskip("eth_tester")
    from ledgerguard.evm import EVMBackend

    ledger = synth.generate_provenance(runs=15, seed=4, batch_size=40)
    chain = EVMBackend.in_memory_chain()
    for i, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{i}", chain.next_prev_digest())
        builder.extend(chunk)
        chain.anchor(builder.seal().commitment)

    report = Verifier(chain, SCHEMA).verify_ledger(ledger.records)
    assert report.intact
