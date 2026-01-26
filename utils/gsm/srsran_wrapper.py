"""
srsRAN Integration for GSM SPY.

Provides wrapper for srsran_cell_search binary to scan for LTE cells.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator

from utils.constants import GSM_CELL_SEARCH_TIMEOUT
from data.gsm_bands import earfcn_to_frequency, get_earfcn_range_for_band

logger = logging.getLogger('intercept.gsm.srsran')


@dataclass
class CellSearchResult:
    """Result from srsRAN cell search."""
    earfcn: int
    pci: int
    frequency_mhz: float
    band: int
    rsrp: float | None = None
    rsrq: float | None = None
    snr: float | None = None
    cp_type: str | None = None  # 'Normal' or 'Extended'
    duplex_mode: str | None = None  # 'FDD' or 'TDD'
    prb: int | None = None  # Number of PRBs (bandwidth indicator)
    phich_duration: str | None = None
    phich_resources: float | None = None
    sfn: int | None = None  # System Frame Number
    mib_data: str | None = None  # Raw MIB hex

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'earfcn': self.earfcn,
            'pci': self.pci,
            'frequency_mhz': self.frequency_mhz,
            'band': self.band,
            'rsrp': self.rsrp,
            'rsrq': self.rsrq,
            'snr': self.snr,
            'cp_type': self.cp_type,
            'duplex_mode': self.duplex_mode,
            'prb': self.prb,
            'phich_duration': self.phich_duration,
            'phich_resources': self.phich_resources,
            'sfn': self.sfn,
            'mib_data': self.mib_data,
        }


# Common installation paths for srsRAN
SRSRAN_PATHS = [
    '/usr/local/bin/srsran_cell_search',
    '/usr/bin/srsran_cell_search',
    '/opt/srsran/bin/srsran_cell_search',
    # Old naming convention (srsLTE)
    '/usr/local/bin/cell_search',
    '/usr/bin/cell_search',
]


def find_srsran_cell_search() -> str | None:
    """
    Find the srsran_cell_search binary.

    Checks PATH and common installation locations.

    Returns:
        Path to binary or None if not found
    """
    # Check PATH first
    for name in ['srsran_cell_search', 'cell_search']:
        path = shutil.which(name)
        if path:
            return path

    # Check common locations
    for path in SRSRAN_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


class SrsRANCellSearch:
    """Wrapper for srsRAN cell search functionality."""

    def __init__(
        self,
        device_index: int = 0,
        device_args: str | None = None,
        gain: float = 40.0
    ):
        """
        Initialize cell search wrapper.

        Args:
            device_index: SDR device index
            device_args: Optional device arguments string
            gain: RF gain (0-100)
        """
        self.device_index = device_index
        self.device_args = device_args or f"driver=rtlsdr,rtl={device_index}"
        self.gain = gain
        self.binary_path = find_srsran_cell_search()
        self._stop_event = threading.Event()
        self._process = None

    def is_available(self) -> bool:
        """Check if srsRAN cell search is available."""
        return self.binary_path is not None

    def scan_earfcn(
        self,
        earfcn: int,
        timeout: int = GSM_CELL_SEARCH_TIMEOUT
    ) -> list[CellSearchResult]:
        """
        Scan a single EARFCN for cells.

        Args:
            earfcn: EARFCN to scan
            timeout: Timeout in seconds

        Returns:
            List of detected cells
        """
        if not self.binary_path:
            raise RuntimeError("srsran_cell_search not found")

        # Build command
        cmd = [
            self.binary_path,
            '-a', self.device_args,
            '-g', str(self.gain),
            '-e', str(earfcn),
        ]

        logger.debug(f"Running cell search: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return self._parse_output(result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            logger.warning(f"Cell search timeout for EARFCN {earfcn}")
            return []
        except Exception as e:
            logger.error(f"Cell search error: {e}")
            return []

    def scan_band(
        self,
        band: int,
        callback: Callable[[CellSearchResult], None] | None = None,
        step: int = 100
    ) -> Generator[CellSearchResult, None, None]:
        """
        Scan an entire LTE band for cells.

        Args:
            band: LTE band number
            callback: Optional callback for each found cell
            step: EARFCN step size for scanning

        Yields:
            CellSearchResult for each detected cell
        """
        earfcn_range = get_earfcn_range_for_band(band)
        if not earfcn_range:
            logger.error(f"Unknown band: {band}")
            return

        min_earfcn, max_earfcn = earfcn_range
        logger.info(f"Scanning band {band}: EARFCN {min_earfcn}-{max_earfcn}")

        for earfcn in range(min_earfcn, max_earfcn + 1, step):
            if self._stop_event.is_set():
                logger.info("Scan stopped")
                return

            cells = self.scan_earfcn(earfcn)
            for cell in cells:
                if callback:
                    callback(cell)
                yield cell

    def scan_bands(
        self,
        bands: list[int],
        callback: Callable[[CellSearchResult], None] | None = None
    ) -> Generator[CellSearchResult, None, None]:
        """
        Scan multiple LTE bands.

        Args:
            bands: List of band numbers to scan
            callback: Optional callback for each found cell

        Yields:
            CellSearchResult for each detected cell
        """
        for band in bands:
            if self._stop_event.is_set():
                return
            yield from self.scan_band(band, callback)

    def stop(self) -> None:
        """Stop any ongoing scan."""
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()

    def reset(self) -> None:
        """Reset for new scan."""
        self._stop_event.clear()

    def _parse_output(self, stdout: str, stderr: str) -> list[CellSearchResult]:
        """
        Parse srsran_cell_search output.

        Output format varies by version but typically includes:
        Found Cell: Mode=FDD, PCI=XXX, EARFCN=XXX, ...
        """
        cells = []

        # Combine stdout and stderr (srsRAN outputs to both)
        output = stdout + '\n' + stderr

        # Pattern for cell detection
        # Example: "Found PLMN: MCC=310, MNC=260, ..."
        # Example: "Found cell: Mode=FDD, PCI=123, ..."
        cell_pattern = re.compile(
            r'Found\s+(?:Cell|cell|PLMN)?[:\s]*'
            r'(?:Mode=(?P<mode>\w+),?\s*)?'
            r'(?:PCI=(?P<pci>\d+),?\s*)?'
            r'(?:EARFCN=(?P<earfcn>\d+),?\s*)?'
            r'(?:PRB=(?P<prb>\d+),?\s*)?'
            r'(?:Freq=(?P<freq>[\d.]+)\s*(?:MHz)?)?',
            re.IGNORECASE
        )

        # Pattern for signal measurements
        rsrp_pattern = re.compile(r'RSRP[=:\s]*(-?\d+\.?\d*)\s*dBm', re.IGNORECASE)
        rsrq_pattern = re.compile(r'RSRQ[=:\s]*(-?\d+\.?\d*)\s*dB', re.IGNORECASE)
        snr_pattern = re.compile(r'SNR[=:\s]*(-?\d+\.?\d*)\s*dB', re.IGNORECASE)
        cp_pattern = re.compile(r'CP[=:\s]*(Normal|Extended)', re.IGNORECASE)

        for line in output.split('\n'):
            match = cell_pattern.search(line)
            if match:
                try:
                    earfcn = int(match.group('earfcn')) if match.group('earfcn') else 0
                    pci = int(match.group('pci')) if match.group('pci') else 0

                    if earfcn == 0 and pci == 0:
                        continue

                    # Get frequency and band from EARFCN
                    freq_info = earfcn_to_frequency(earfcn)
                    if freq_info:
                        band, freq_mhz = freq_info
                    else:
                        band = 0
                        freq_mhz = float(match.group('freq')) if match.group('freq') else 0.0

                    cell = CellSearchResult(
                        earfcn=earfcn,
                        pci=pci,
                        frequency_mhz=freq_mhz,
                        band=band,
                        duplex_mode=match.group('mode'),
                        prb=int(match.group('prb')) if match.group('prb') else None,
                    )

                    # Extract signal measurements from nearby lines
                    rsrp_match = rsrp_pattern.search(line)
                    if rsrp_match:
                        cell.rsrp = float(rsrp_match.group(1))

                    rsrq_match = rsrq_pattern.search(line)
                    if rsrq_match:
                        cell.rsrq = float(rsrq_match.group(1))

                    snr_match = snr_pattern.search(line)
                    if snr_match:
                        cell.snr = float(snr_match.group(1))

                    cp_match = cp_pattern.search(line)
                    if cp_match:
                        cell.cp_type = cp_match.group(1)

                    cells.append(cell)

                except (ValueError, AttributeError) as e:
                    logger.debug(f"Failed to parse line: {line}, error: {e}")
                    continue

        return cells


def check_srsran_tools() -> dict:
    """
    Check for srsRAN tool availability.

    Returns:
        Dictionary with tool status
    """
    cell_search = find_srsran_cell_search()

    return {
        'srsran_cell_search': {
            'available': cell_search is not None,
            'path': cell_search,
        },
        'version': _get_srsran_version(cell_search) if cell_search else None,
    }


def _get_srsran_version(binary_path: str) -> str | None:
    """Get srsRAN version string."""
    try:
        result = subprocess.run(
            [binary_path, '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Version is usually on first line
        output = result.stdout or result.stderr
        if output:
            return output.strip().split('\n')[0]
    except Exception:
        pass
    return None
