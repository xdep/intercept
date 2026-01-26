"""
Cell Tower Database utilities for GSM SPY.

Manages a separate SQLite database (gsm_cells.db) for OpenCellID cell tower data.
Uses R-tree spatial indexing for fast geo-queries.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Callable

logger = logging.getLogger('intercept.gsm.cell_database')

# Database file location (separate from main intercept.db)
DB_DIR = Path(__file__).parent.parent.parent / 'instance'
CELL_DB_PATH = DB_DIR / 'gsm_cells.db'

# Thread-local storage for connections
_local = threading.local()


def get_cell_db_path() -> Path:
    """Get the cell tower database file path, creating directory if needed."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    return CELL_DB_PATH


def get_cell_connection() -> sqlite3.Connection:
    """Get a thread-local cell tower database connection."""
    if not hasattr(_local, 'cell_connection') or _local.cell_connection is None:
        db_path = get_cell_db_path()
        _local.cell_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        _local.cell_connection.row_factory = sqlite3.Row
        # Enable foreign keys
        _local.cell_connection.execute('PRAGMA foreign_keys = ON')
    return _local.cell_connection


@contextmanager
def get_cell_db():
    """Context manager for cell tower database operations."""
    conn = get_cell_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_cell_db() -> None:
    """Initialize the cell tower database schema with R-tree spatial index."""
    db_path = get_cell_db_path()
    logger.info(f"Initializing cell tower database at {db_path}")

    with get_cell_db() as conn:
        # Main cell towers table (OpenCellID format)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS cell_towers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                radio TEXT NOT NULL,
                mcc INTEGER NOT NULL,
                mnc INTEGER NOT NULL,
                lac INTEGER NOT NULL,
                cell_id INTEGER NOT NULL,
                unit INTEGER,
                lon REAL NOT NULL,
                lat REAL NOT NULL,
                range INTEGER,
                samples INTEGER,
                changeable INTEGER,
                created INTEGER,
                updated INTEGER,
                average_signal INTEGER,
                UNIQUE(mcc, mnc, lac, cell_id)
            )
        ''')

        # Create R-tree spatial index for fast geo-queries
        conn.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS cell_towers_rtree USING rtree(
                id,
                min_lon, max_lon,
                min_lat, max_lat
            )
        ''')

        # Indexes for common queries
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cell_towers_mcc
            ON cell_towers(mcc)
        ''')

        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cell_towers_mcc_mnc
            ON cell_towers(mcc, mnc)
        ''')

        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cell_towers_radio
            ON cell_towers(radio)
        ''')

        logger.info("Cell tower database initialized successfully")


def close_cell_db() -> None:
    """Close the thread-local cell tower database connection."""
    if hasattr(_local, 'cell_connection') and _local.cell_connection is not None:
        _local.cell_connection.close()
        _local.cell_connection = None


def import_cell_towers_csv(
    csv_path: str,
    progress_callback: Callable[[int, int], None] | None = None,
    batch_size: int = 10000
) -> int:
    """
    Bulk import cell towers from OpenCellID CSV file.

    CSV format: radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal

    Args:
        csv_path: Path to the CSV file
        progress_callback: Optional callback(rows_imported, total_rows) for progress updates
        batch_size: Number of rows to insert per batch

    Returns:
        Number of rows imported
    """
    csv_file = Path(csv_path)
    if not csv_file.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    # Count total rows for progress
    logger.info(f"Counting rows in {csv_path}...")
    total_rows = sum(1 for _ in open(csv_file, 'r', encoding='utf-8')) - 1  # Subtract header

    logger.info(f"Importing {total_rows:,} cell towers from {csv_path}")

    rows_imported = 0
    batch = []

    with get_cell_db() as conn:
        # Clear existing data
        conn.execute('DELETE FROM cell_towers_rtree')
        conn.execute('DELETE FROM cell_towers')
        conn.commit()

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                try:
                    # Parse row data
                    radio = row.get('radio', '')
                    mcc = int(row.get('mcc', 0))
                    mnc = int(row.get('net', row.get('mnc', 0)))
                    lac = int(row.get('area', row.get('lac', 0)))
                    cell_id = int(row.get('cell', row.get('cell_id', 0)))
                    unit = int(row.get('unit', 0)) if row.get('unit') else None
                    lon = float(row.get('lon', row.get('longitude', 0)))
                    lat = float(row.get('lat', row.get('latitude', 0)))
                    range_m = int(row.get('range', 0)) if row.get('range') else None
                    samples = int(row.get('samples', 0)) if row.get('samples') else None
                    changeable = int(row.get('changeable', 0)) if row.get('changeable') else None
                    created = int(row.get('created', 0)) if row.get('created') else None
                    updated = int(row.get('updated', 0)) if row.get('updated') else None
                    avg_signal = int(row.get('averageSignal', 0)) if row.get('averageSignal') else None

                    # Skip invalid coordinates
                    if not (-180 <= lon <= 180 and -90 <= lat <= 90):
                        continue

                    batch.append((
                        radio, mcc, mnc, lac, cell_id, unit,
                        lon, lat, range_m, samples, changeable,
                        created, updated, avg_signal
                    ))

                    if len(batch) >= batch_size:
                        _insert_batch(conn, batch)
                        rows_imported += len(batch)
                        batch = []

                        if progress_callback:
                            progress_callback(rows_imported, total_rows)

                        # Log progress every 100k rows
                        if rows_imported % 100000 == 0:
                            logger.info(f"Imported {rows_imported:,} / {total_rows:,} rows ({100*rows_imported/total_rows:.1f}%)")

                except (ValueError, KeyError) as e:
                    # Skip malformed rows
                    continue

            # Insert remaining batch
            if batch:
                _insert_batch(conn, batch)
                rows_imported += len(batch)

        # Populate R-tree index
        logger.info("Building R-tree spatial index...")
        conn.execute('''
            INSERT INTO cell_towers_rtree (id, min_lon, max_lon, min_lat, max_lat)
            SELECT id, lon, lon, lat, lat FROM cell_towers
        ''')
        conn.commit()

    logger.info(f"Import complete: {rows_imported:,} cell towers imported")
    return rows_imported


def _insert_batch(conn: sqlite3.Connection, batch: list) -> None:
    """Insert a batch of cell tower records."""
    conn.executemany('''
        INSERT OR IGNORE INTO cell_towers
        (radio, mcc, mnc, lac, cell_id, unit, lon, lat, range, samples, changeable, created, updated, average_signal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', batch)
    conn.commit()


def get_nearby_towers(
    lat: float,
    lon: float,
    radius_km: float = 50,
    radio_type: str | None = None,
    limit: int = 100
) -> list[dict]:
    """
    Find cell towers near a location using R-tree spatial query.

    Args:
        lat: Latitude of center point
        lon: Longitude of center point
        radius_km: Search radius in kilometers
        radio_type: Optional filter by radio type (LTE, GSM, UMTS, CDMA, NR)
        limit: Maximum number of results

    Returns:
        List of cell tower records with distance
    """
    # Convert km to approximate degrees (1 degree ~= 111 km at equator)
    radius_deg = radius_km / 111.0

    with get_cell_db() as conn:
        if radio_type:
            cursor = conn.execute('''
                SELECT t.*, r.id as rtree_id
                FROM cell_towers t
                JOIN cell_towers_rtree r ON t.id = r.id
                WHERE r.min_lon >= ? AND r.max_lon <= ?
                  AND r.min_lat >= ? AND r.max_lat <= ?
                  AND t.radio = ?
                ORDER BY ((t.lat - ?) * (t.lat - ?) + (t.lon - ?) * (t.lon - ?))
                LIMIT ?
            ''', (
                lon - radius_deg, lon + radius_deg,
                lat - radius_deg, lat + radius_deg,
                radio_type,
                lat, lat, lon, lon,
                limit
            ))
        else:
            cursor = conn.execute('''
                SELECT t.*, r.id as rtree_id
                FROM cell_towers t
                JOIN cell_towers_rtree r ON t.id = r.id
                WHERE r.min_lon >= ? AND r.max_lon <= ?
                  AND r.min_lat >= ? AND r.max_lat <= ?
                ORDER BY ((t.lat - ?) * (t.lat - ?) + (t.lon - ?) * (t.lon - ?))
                LIMIT ?
            ''', (
                lon - radius_deg, lon + radius_deg,
                lat - radius_deg, lat + radius_deg,
                lat, lat, lon, lon,
                limit
            ))

        results = []
        for row in cursor:
            tower = dict(row)
            # Calculate approximate distance
            tower['distance_km'] = _haversine_distance(lat, lon, tower['lat'], tower['lon'])
            results.append(tower)

        return results


def get_tower_by_id(mcc: int, mnc: int, lac: int, cell_id: int) -> dict | None:
    """
    Get a specific cell tower by its identifiers.

    Args:
        mcc: Mobile Country Code
        mnc: Mobile Network Code
        lac: Location Area Code
        cell_id: Cell ID

    Returns:
        Cell tower record or None if not found
    """
    with get_cell_db() as conn:
        cursor = conn.execute('''
            SELECT * FROM cell_towers
            WHERE mcc = ? AND mnc = ? AND lac = ? AND cell_id = ?
        ''', (mcc, mnc, lac, cell_id))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_towers_by_mcc(mcc: int, limit: int = 1000) -> list[dict]:
    """
    Get cell towers by Mobile Country Code.

    Args:
        mcc: Mobile Country Code
        limit: Maximum number of results

    Returns:
        List of cell tower records
    """
    with get_cell_db() as conn:
        cursor = conn.execute('''
            SELECT * FROM cell_towers
            WHERE mcc = ?
            LIMIT ?
        ''', (mcc, limit))
        return [dict(row) for row in cursor]


def get_tower_count() -> int:
    """Get the total number of cell towers in the database."""
    with get_cell_db() as conn:
        cursor = conn.execute('SELECT COUNT(*) FROM cell_towers')
        return cursor.fetchone()[0]


def get_database_stats() -> dict:
    """Get statistics about the cell tower database."""
    with get_cell_db() as conn:
        stats = {}

        # Total count
        cursor = conn.execute('SELECT COUNT(*) FROM cell_towers')
        stats['total_towers'] = cursor.fetchone()[0]

        # Count by radio type
        cursor = conn.execute('''
            SELECT radio, COUNT(*) as count
            FROM cell_towers
            GROUP BY radio
            ORDER BY count DESC
        ''')
        stats['by_radio'] = {row['radio']: row['count'] for row in cursor}

        # Count by top MCCs
        cursor = conn.execute('''
            SELECT mcc, COUNT(*) as count
            FROM cell_towers
            GROUP BY mcc
            ORDER BY count DESC
            LIMIT 20
        ''')
        stats['top_mccs'] = {row['mcc']: row['count'] for row in cursor}

        return stats


def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two coordinates using Haversine formula.

    Returns:
        Distance in kilometers
    """
    import math

    R = 6371  # Earth radius in km

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = (math.sin(delta_lat / 2) ** 2 +
         math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c
