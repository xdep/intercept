"""
GSM SPY - Cellular Intelligence Module

Provides passive LTE/GSM tower detection, client tracking, IMSI catcher detection,
and regional band management for the INTERCEPT platform.
"""

from __future__ import annotations

from .cell_database import (
    init_cell_db,
    get_cell_db,
    import_cell_towers_csv,
    get_nearby_towers,
    get_tower_by_id,
    get_towers_by_mcc,
    get_tower_count,
    get_database_stats,
)

from .region_detector import (
    detect_region,
    get_scan_bands,
    RegionInfo,
)

from .timing_advance import (
    CellularTechnology,
    DistanceEstimate,
    calculate_distance_from_ta,
    ta_to_ring_coordinates,
)

from .fingerprint import (
    RFFingerprint,
    create_fingerprint,
    fingerprint_to_hash,
)

from .alert_engine import (
    AlertType,
    AlertSeverity,
    GSMAlert,
    AlertEngine,
)

from .srsran_wrapper import (
    CellSearchResult,
    find_srsran_cell_search,
    SrsRANCellSearch,
)

__all__ = [
    # Cell database
    'init_cell_db',
    'get_cell_db',
    'import_cell_towers_csv',
    'get_nearby_towers',
    'get_tower_by_id',
    'get_towers_by_mcc',
    'get_tower_count',
    'get_database_stats',
    # Region detection
    'detect_region',
    'get_scan_bands',
    'RegionInfo',
    # Timing advance
    'CellularTechnology',
    'DistanceEstimate',
    'calculate_distance_from_ta',
    'ta_to_ring_coordinates',
    # Fingerprinting
    'RFFingerprint',
    'create_fingerprint',
    'fingerprint_to_hash',
    # Alert engine
    'AlertType',
    'AlertSeverity',
    'GSMAlert',
    'AlertEngine',
    # srsRAN
    'CellSearchResult',
    'find_srsran_cell_search',
    'SrsRANCellSearch',
]
