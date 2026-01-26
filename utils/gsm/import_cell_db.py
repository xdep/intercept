"""
Cell Tower Database Import Utility.

Command-line utility to import OpenCellID CSV data into the gsm_cells.db database.

Usage:
    python -m utils.gsm.import_cell_db /path/to/cell_towers.csv
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def progress_bar(current: int, total: int, width: int = 50) -> str:
    """Generate a progress bar string."""
    percent = current / total if total > 0 else 0
    filled = int(width * percent)
    bar = '=' * filled + '-' * (width - filled)
    return f'[{bar}] {percent*100:.1f}% ({current:,}/{total:,})'


def main():
    """Main entry point for cell tower import."""
    parser = argparse.ArgumentParser(
        description='Import OpenCellID cell tower data into GSM SPY database',
        epilog='The CSV file should be in OpenCellID format.'
    )
    parser.add_argument(
        'csv_file',
        type=str,
        help='Path to the OpenCellID CSV file'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=10000,
        help='Number of rows per batch (default: 10000)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )

    args = parser.parse_args()

    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    # Import here to avoid circular imports
    from utils.gsm.cell_database import init_cell_db, import_cell_towers_csv, get_database_stats

    print("=" * 60)
    print("  GSM SPY - Cell Tower Database Import")
    print("=" * 60)
    print()
    print(f"Source: {csv_path}")
    print(f"Size: {csv_path.stat().st_size / (1024*1024):.1f} MB")
    print()

    # Initialize database
    print("Initializing database...")
    init_cell_db()
    print()

    # Progress callback
    last_update = [0]
    start_time = time.time()

    def on_progress(current: int, total: int):
        if args.quiet:
            return
        # Update every 1%
        if current - last_update[0] >= total // 100:
            elapsed = time.time() - start_time
            rate = current / elapsed if elapsed > 0 else 0
            eta = (total - current) / rate if rate > 0 else 0
            print(f"\r{progress_bar(current, total)} | {rate:,.0f} rows/sec | ETA: {eta:.0f}s", end='', flush=True)
            last_update[0] = current

    # Import data
    print("Importing cell towers...")
    try:
        rows_imported = import_cell_towers_csv(
            str(csv_path),
            progress_callback=on_progress,
            batch_size=args.batch_size
        )
    except Exception as e:
        print(f"\nError during import: {e}")
        sys.exit(1)

    elapsed = time.time() - start_time
    print()
    print()
    print("=" * 60)
    print("  Import Complete")
    print("=" * 60)
    print(f"  Rows imported: {rows_imported:,}")
    print(f"  Time elapsed:  {elapsed:.1f} seconds")
    print(f"  Import rate:   {rows_imported/elapsed:,.0f} rows/second")
    print()

    # Show database stats
    print("Database Statistics:")
    stats = get_database_stats()
    print(f"  Total towers: {stats['total_towers']:,}")
    print()
    print("  By radio type:")
    for radio, count in stats['by_radio'].items():
        print(f"    {radio}: {count:,}")
    print()
    print("  Top countries (by MCC):")
    for mcc, count in list(stats['top_mccs'].items())[:10]:
        print(f"    MCC {mcc}: {count:,}")
    print()

    # Show database file size
    from utils.gsm.cell_database import CELL_DB_PATH
    if CELL_DB_PATH.exists():
        size_mb = CELL_DB_PATH.stat().st_size / (1024 * 1024)
        print(f"Database file: {CELL_DB_PATH}")
        print(f"Database size: {size_mb:.1f} MB")


if __name__ == '__main__':
    main()
