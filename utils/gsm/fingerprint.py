"""
RF Fingerprinting for GSM SPY.

Creates unique fingerprints from RF characteristics to identify and track
cell towers across sessions, useful for anomaly detection.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class RFFingerprint:
    """RF signature fingerprint for a cell tower."""
    pci: int  # Physical Cell ID
    earfcn: int  # EARFCN (frequency channel)
    bandwidth_mhz: float | None = None
    cp_type: str | None = None  # Cyclic prefix type (normal/extended)
    antenna_ports: int | None = None
    mib_crc: str | None = None  # CRC of MIB data
    sib1_crc: str | None = None  # CRC of SIB1 data
    rsrp_variance: float | None = None  # Signal strength variance over time
    timing_offset: int | None = None  # Frame timing offset
    frequency_offset_hz: float | None = None  # Frequency error
    duplex_mode: str | None = None  # FDD or TDD

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'RFFingerprint':
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def create_fingerprint(
    pci: int,
    earfcn: int,
    bandwidth_mhz: float | None = None,
    cp_type: str | None = None,
    antenna_ports: int | None = None,
    mib_data: bytes | None = None,
    sib1_data: bytes | None = None,
    rsrp_samples: list[float] | None = None,
    timing_offset: int | None = None,
    frequency_offset_hz: float | None = None,
    duplex_mode: str | None = None
) -> RFFingerprint:
    """
    Create an RF fingerprint from cell characteristics.

    Args:
        pci: Physical Cell ID
        earfcn: EARFCN value
        bandwidth_mhz: System bandwidth in MHz
        cp_type: Cyclic prefix type
        antenna_ports: Number of antenna ports
        mib_data: Raw MIB data bytes
        sib1_data: Raw SIB1 data bytes
        rsrp_samples: List of RSRP measurements for variance calculation
        timing_offset: Frame timing offset
        frequency_offset_hz: Frequency offset in Hz
        duplex_mode: FDD or TDD

    Returns:
        RFFingerprint object
    """
    # Calculate MIB CRC if data provided
    mib_crc = None
    if mib_data:
        mib_crc = hashlib.sha256(mib_data).hexdigest()[:16]

    # Calculate SIB1 CRC if data provided
    sib1_crc = None
    if sib1_data:
        sib1_crc = hashlib.sha256(sib1_data).hexdigest()[:16]

    # Calculate RSRP variance if samples provided
    rsrp_variance = None
    if rsrp_samples and len(rsrp_samples) >= 2:
        mean = sum(rsrp_samples) / len(rsrp_samples)
        rsrp_variance = sum((x - mean) ** 2 for x in rsrp_samples) / len(rsrp_samples)

    return RFFingerprint(
        pci=pci,
        earfcn=earfcn,
        bandwidth_mhz=bandwidth_mhz,
        cp_type=cp_type,
        antenna_ports=antenna_ports,
        mib_crc=mib_crc,
        sib1_crc=sib1_crc,
        rsrp_variance=rsrp_variance,
        timing_offset=timing_offset,
        frequency_offset_hz=frequency_offset_hz,
        duplex_mode=duplex_mode
    )


def fingerprint_to_hash(fp: RFFingerprint) -> str:
    """
    Generate a unique hash from a fingerprint.

    The hash is based on the immutable characteristics of the cell
    (PCI, EARFCN, bandwidth, CP type, antenna config).

    Args:
        fp: RFFingerprint object

    Returns:
        64-character hex hash string
    """
    # Create a stable string representation
    key_data = {
        'pci': fp.pci,
        'earfcn': fp.earfcn,
        'bandwidth': fp.bandwidth_mhz,
        'cp': fp.cp_type,
        'antennas': fp.antenna_ports,
        'duplex': fp.duplex_mode,
    }

    # Add MIB/SIB CRCs if available (these identify the cell configuration)
    if fp.mib_crc:
        key_data['mib'] = fp.mib_crc
    if fp.sib1_crc:
        key_data['sib1'] = fp.sib1_crc

    # Create deterministic JSON string
    json_str = json.dumps(key_data, sort_keys=True, separators=(',', ':'))

    return hashlib.sha256(json_str.encode()).hexdigest()


def compare_fingerprints(fp1: RFFingerprint, fp2: RFFingerprint) -> float:
    """
    Compare two fingerprints and return similarity score.

    Args:
        fp1: First fingerprint
        fp2: Second fingerprint

    Returns:
        Similarity score from 0.0 (different) to 1.0 (identical)
    """
    score = 0.0
    max_score = 0.0

    # PCI match (required)
    max_score += 30
    if fp1.pci == fp2.pci:
        score += 30

    # EARFCN match (required)
    max_score += 30
    if fp1.earfcn == fp2.earfcn:
        score += 30

    # Bandwidth match
    if fp1.bandwidth_mhz is not None and fp2.bandwidth_mhz is not None:
        max_score += 10
        if fp1.bandwidth_mhz == fp2.bandwidth_mhz:
            score += 10

    # CP type match
    if fp1.cp_type is not None and fp2.cp_type is not None:
        max_score += 5
        if fp1.cp_type == fp2.cp_type:
            score += 5

    # Antenna ports match
    if fp1.antenna_ports is not None and fp2.antenna_ports is not None:
        max_score += 5
        if fp1.antenna_ports == fp2.antenna_ports:
            score += 5

    # MIB CRC match (strong indicator)
    if fp1.mib_crc is not None and fp2.mib_crc is not None:
        max_score += 10
        if fp1.mib_crc == fp2.mib_crc:
            score += 10

    # Duplex mode match
    if fp1.duplex_mode is not None and fp2.duplex_mode is not None:
        max_score += 5
        if fp1.duplex_mode == fp2.duplex_mode:
            score += 5

    # Timing characteristics (allow some variance)
    if fp1.timing_offset is not None and fp2.timing_offset is not None:
        max_score += 5
        if abs(fp1.timing_offset - fp2.timing_offset) < 10:
            score += 5

    return score / max_score if max_score > 0 else 0.0


def is_same_cell(fp1: RFFingerprint, fp2: RFFingerprint, threshold: float = 0.8) -> bool:
    """
    Determine if two fingerprints represent the same cell.

    Args:
        fp1: First fingerprint
        fp2: Second fingerprint
        threshold: Minimum similarity score (0.0-1.0)

    Returns:
        True if fingerprints likely represent the same cell
    """
    return compare_fingerprints(fp1, fp2) >= threshold
