"""GSM SPY cellular intelligence routes."""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Generator

from flask import Blueprint, jsonify, request, Response, render_template

import app as app_module
from utils.logging import get_logger
from utils.validation import validate_device_index, validate_gain
from utils.sse import format_sse
from utils.sdr import SDRFactory, SDRType
from utils.constants import (
    GSM_TERMINATE_TIMEOUT,
    GSM_UPDATE_INTERVAL,
    SSE_KEEPALIVE_INTERVAL,
    SSE_QUEUE_TIMEOUT,
    QUEUE_MAX_SIZE,
    MAX_GSM_TOWER_AGE_SECONDS,
    MAX_GSM_CLIENT_AGE_SECONDS,
)
from utils.database import (
    create_gsm_session,
    update_gsm_session,
    get_gsm_session,
    add_gsm_tower,
    get_gsm_towers,
    add_gsm_client,
    get_gsm_clients,
    add_gsm_alert,
    get_gsm_alerts,
    acknowledge_gsm_alert,
    get_gsm_alert_summary,
)
from utils.gsm import (
    init_cell_db,
    get_nearby_towers,
    get_tower_by_id,
    get_tower_count,
    get_database_stats,
    detect_region,
    get_scan_bands,
    CellSearchResult,
    find_srsran_cell_search,
    SrsRANCellSearch,
    AlertEngine,
    AlertType,
    AlertSeverity,
    calculate_distance_from_ta,
    CellularTechnology,
)
from utils.gsm.alert_engine import get_privacy_warning
from data.gsm_bands import (
    get_bands_for_country,
    earfcn_to_frequency,
    get_band,
    LTE_BANDS,
)

logger = get_logger('intercept.gsm')

gsm_bp = Blueprint('gsm', __name__, url_prefix='/gsm')

# Module-level state
gsm_running = False
gsm_session_id = None
gsm_start_time = None
gsm_active_device = None
gsm_privacy_mode = 'standard'
gsm_scanner = None
gsm_alert_engine = None


def init_gsm_state(gsm_queue, gsm_lock):
    """Initialize GSM state with queue and lock from app."""
    global _gsm_queue, _gsm_lock
    _gsm_queue = gsm_queue
    _gsm_lock = gsm_lock

    # Initialize cell tower database
    try:
        init_cell_db()
        logger.info("Cell tower database initialized")
    except Exception as e:
        logger.warning(f"Could not initialize cell tower database: {e}")


# =============================================================================
# Tool and Status Endpoints
# =============================================================================

@gsm_bp.route('/tools')
def check_gsm_tools():
    """Check for GSM decoding tools and hardware."""
    srsran_path = find_srsran_cell_search()

    # Check SDR devices
    devices = SDRFactory.detect_devices()

    # Check cell tower database
    try:
        tower_count = get_tower_count()
        db_available = True
    except Exception:
        tower_count = 0
        db_available = False

    return jsonify({
        'srsran_cell_search': {
            'available': srsran_path is not None,
            'path': srsran_path,
        },
        'sdr_devices': [d.to_dict() for d in devices],
        'device_count': len(devices),
        'cell_database': {
            'available': db_available,
            'tower_count': tower_count,
        }
    })


@gsm_bp.route('/status')
def gsm_status():
    """Get GSM tracking status."""
    process_running = False
    if hasattr(app_module, 'gsm_process') and app_module.gsm_process:
        process_running = app_module.gsm_process.poll() is None

    session_duration = None
    if gsm_start_time:
        session_duration = int(time.time() - gsm_start_time)

    return jsonify({
        'tracking_active': gsm_running,
        'session_id': gsm_session_id,
        'session_duration': session_duration,
        'active_device': gsm_active_device,
        'privacy_mode': gsm_privacy_mode,
        'process_running': process_running,
        'tower_count': len(app_module.gsm_towers) if hasattr(app_module, 'gsm_towers') else 0,
        'client_count': len(app_module.gsm_clients) if hasattr(app_module, 'gsm_clients') else 0,
        'queue_size': app_module.gsm_queue.qsize() if hasattr(app_module, 'gsm_queue') else 0,
        'srsran_available': find_srsran_cell_search() is not None,
    })


# =============================================================================
# Region Management
# =============================================================================

@gsm_bp.route('/region', methods=['GET'])
def get_region():
    """Get current region configuration."""
    region_info = detect_region()

    return jsonify({
        'country_code': region_info.country_code,
        'country_name': region_info.country_name,
        'detection_method': region_info.detection_method,
        'confidence': region_info.confidence,
        'bands': region_info.bands,
        'available_bands': list(LTE_BANDS.keys()),
    })


@gsm_bp.route('/region', methods=['POST'])
def set_region():
    """Set manual region override."""
    data = request.json or {}
    country_code = data.get('country_code')

    if not country_code:
        return jsonify({'status': 'error', 'message': 'country_code required'}), 400

    region_info = detect_region(country_code.upper())

    return jsonify({
        'status': 'success',
        'country_code': region_info.country_code,
        'country_name': region_info.country_name,
        'bands': region_info.bands,
    })


# =============================================================================
# Privacy Mode
# =============================================================================

@gsm_bp.route('/privacy', methods=['GET'])
def get_privacy():
    """Get current privacy mode."""
    return jsonify({
        'mode': gsm_privacy_mode,
        'modes': {
            'standard': 'No IMSI/TMSI capture',
            'strict': 'Minimal data collection',
            'research': 'Full capture (requires authorization)',
        }
    })


@gsm_bp.route('/privacy', methods=['POST'])
def set_privacy():
    """Set privacy mode."""
    global gsm_privacy_mode

    data = request.json or {}
    mode = data.get('mode', 'standard')

    if mode not in ['standard', 'strict', 'research']:
        return jsonify({'status': 'error', 'message': 'Invalid mode'}), 400

    if mode == 'research':
        # Return warning for research mode
        return jsonify({
            'status': 'warning',
            'mode': mode,
            'warning': get_privacy_warning(),
            'requires_confirmation': True,
        })

    gsm_privacy_mode = mode
    return jsonify({'status': 'success', 'mode': mode})


@gsm_bp.route('/privacy/confirm', methods=['POST'])
def confirm_privacy():
    """Confirm research mode enablement."""
    global gsm_privacy_mode

    data = request.json or {}
    if data.get('confirmed') and data.get('mode') == 'research':
        gsm_privacy_mode = 'research'
        logger.warning("GSM SPY Research Mode enabled - IMSI capture active")
        return jsonify({'status': 'success', 'mode': 'research'})

    return jsonify({'status': 'error', 'message': 'Confirmation required'}), 400


# =============================================================================
# Scanning Control
# =============================================================================

@gsm_bp.route('/start', methods=['POST'])
def start_gsm():
    """Start GSM cell scanning."""
    global gsm_running, gsm_session_id, gsm_start_time, gsm_active_device
    global gsm_scanner, gsm_alert_engine

    with app_module.gsm_lock:
        if gsm_running:
            return jsonify({'status': 'already_running', 'message': 'GSM scanning already active'}), 409

    data = request.json or {}

    # Validate inputs
    try:
        gain = float(validate_gain(data.get('gain', '40')))
        device = validate_device_index(data.get('device', '0'))
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

    # Check for srsRAN
    if not find_srsran_cell_search():
        return jsonify({
            'status': 'error',
            'message': 'srsran_cell_search not found. Install srsRAN 4G from https://github.com/srsran/srsRAN_4G'
        }), 400

    # Get region and bands
    region_code = data.get('region')
    bands_override = data.get('bands')
    privacy_mode = data.get('privacy_mode', 'standard')

    region_info = detect_region(region_code)
    bands = bands_override if bands_override else region_info.bands

    # Create session
    gsm_session_id = create_gsm_session(
        device_index=device,
        sdr_type='rtlsdr',
        gain=gain,
        region=region_info.country_code,
        bands=bands,
        privacy_mode=privacy_mode
    )

    # Initialize scanner and alert engine
    gsm_scanner = SrsRANCellSearch(
        device_index=device,
        gain=gain
    )

    gsm_alert_engine = AlertEngine(
        nearby_towers_func=lambda lat, lon, r: get_nearby_towers(lat, lon, r)
    )

    # Clear data stores
    app_module.gsm_towers.clear()
    app_module.gsm_clients.clear()

    gsm_running = True
    gsm_start_time = time.time()
    gsm_active_device = device

    # Start scanning thread
    scan_thread = threading.Thread(
        target=_scan_worker,
        args=(bands, gain, device),
        daemon=True
    )
    scan_thread.start()

    logger.info(f"GSM scanning started on device {device}, bands: {bands}")

    return jsonify({
        'status': 'started',
        'session_id': gsm_session_id,
        'device': device,
        'bands': bands,
        'region': region_info.country_code,
    })


@gsm_bp.route('/stop', methods=['POST'])
def stop_gsm():
    """Stop GSM scanning."""
    global gsm_running, gsm_scanner, gsm_active_device

    with app_module.gsm_lock:
        gsm_running = False

        if gsm_scanner:
            gsm_scanner.stop()
            gsm_scanner = None

        # Update session
        if gsm_session_id:
            update_gsm_session(
                gsm_session_id,
                status='stopped',
                towers_found=len(app_module.gsm_towers),
                clients_observed=len(app_module.gsm_clients),
                stopped=True
            )

        gsm_active_device = None

    logger.info("GSM scanning stopped")
    return jsonify({'status': 'stopped'})


def _scan_worker(bands: list[int], gain: float, device: int):
    """Background worker for cell scanning."""
    global gsm_running, gsm_scanner

    logger.info(f"Scan worker started for bands: {bands}")

    observer_lat = None
    observer_lon = None

    while gsm_running and gsm_scanner:
        try:
            for cell in gsm_scanner.scan_bands(bands):
                if not gsm_running:
                    break

                # Process detected cell
                _process_cell(cell, observer_lat, observer_lon)

        except Exception as e:
            logger.error(f"Scan worker error: {e}")
            time.sleep(1)

    logger.info("Scan worker stopped")


def _process_cell(cell: CellSearchResult, observer_lat: float | None, observer_lon: float | None):
    """Process a detected cell and update stores."""
    global gsm_alert_engine

    # Create tower data dict
    tower_data = cell.to_dict()
    tower_key = f"{cell.earfcn}_{cell.pci}"

    # Check if tower is in database
    in_database = False
    db_distance = None
    if cell.frequency_mhz and observer_lat and observer_lon:
        nearby = get_nearby_towers(observer_lat, observer_lon, 50, 'LTE', 10)
        for db_tower in nearby:
            if db_tower.get('cell_id') == cell.pci:  # Simplified match
                in_database = True
                db_distance = db_tower.get('distance_km')
                break

    tower_data['in_database'] = in_database
    tower_data['database_match_distance_km'] = db_distance

    # Run alert analysis
    if gsm_alert_engine:
        alerts = gsm_alert_engine.analyze_tower(tower_data, observer_lat, observer_lon)
        tower_data['stingray_score'] = tower_data.get('stingray_score', 0)

        # Store alerts
        for alert in alerts:
            add_gsm_alert(
                session_id=gsm_session_id,
                alert_type=alert.alert_type.value,
                severity=alert.severity.value,
                title=alert.title,
                description=alert.description,
                score=alert.score,
                evidence=alert.evidence
            )

            # Send alert via SSE
            try:
                app_module.gsm_queue.put_nowait({
                    'type': 'alert',
                    **alert.to_dict()
                })
            except queue.Full:
                pass

    # Store tower
    app_module.gsm_towers.set(tower_key, tower_data)

    # Save to database
    add_gsm_tower(
        session_id=gsm_session_id,
        earfcn=cell.earfcn,
        pci=cell.pci,
        frequency_mhz=cell.frequency_mhz,
        rsrp=cell.rsrp,
        rsrq=cell.rsrq,
        snr=cell.snr,
        encryption=None,
        stingray_score=tower_data.get('stingray_score', 0),
        in_database=in_database,
        database_match_distance_km=db_distance,
    )

    # Send via SSE
    try:
        app_module.gsm_queue.put_nowait({
            'type': 'tower',
            **tower_data
        })
    except queue.Full:
        pass


# =============================================================================
# SSE Streaming
# =============================================================================

@gsm_bp.route('/stream')
def stream_gsm():
    """SSE stream for GSM data."""
    def generate() -> Generator[str, None, None]:
        last_keepalive = time.time()

        while True:
            try:
                msg = app_module.gsm_queue.get(timeout=SSE_QUEUE_TIMEOUT)
                last_keepalive = time.time()
                yield format_sse(msg)
            except queue.Empty:
                now = time.time()
                if now - last_keepalive >= SSE_KEEPALIVE_INTERVAL:
                    yield format_sse({'type': 'keepalive'})
                    last_keepalive = now

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


# =============================================================================
# Data Endpoints
# =============================================================================

@gsm_bp.route('/towers')
def get_towers():
    """Get detected towers."""
    towers = list(app_module.gsm_towers.values()) if hasattr(app_module, 'gsm_towers') else []
    return jsonify({
        'towers': towers,
        'count': len(towers)
    })


@gsm_bp.route('/clients')
def get_clients_endpoint():
    """Get observed clients."""
    # Respect privacy mode
    if gsm_privacy_mode == 'strict':
        return jsonify({
            'clients': [],
            'count': 0,
            'privacy_restricted': True
        })

    clients = list(app_module.gsm_clients.values()) if hasattr(app_module, 'gsm_clients') else []

    # Mask IMSI in standard mode
    if gsm_privacy_mode == 'standard':
        for client in clients:
            if client.get('imsi'):
                client['imsi'] = client['imsi'][:6] + '********'

    return jsonify({
        'clients': clients,
        'count': len(clients)
    })


@gsm_bp.route('/alerts')
def get_alerts_endpoint():
    """Get security alerts."""
    session_id = request.args.get('session_id', type=int)
    severity = request.args.get('severity')
    acknowledged = request.args.get('acknowledged')

    if acknowledged is not None:
        acknowledged = acknowledged.lower() == 'true'

    alerts = get_gsm_alerts(
        session_id=session_id or gsm_session_id,
        severity=severity,
        acknowledged=acknowledged,
        limit=100
    )

    summary = get_gsm_alert_summary()

    return jsonify({
        'alerts': alerts,
        'summary': summary
    })


@gsm_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id: int):
    """Acknowledge a security alert."""
    data = request.json or {}
    notes = data.get('notes')

    success = acknowledge_gsm_alert(alert_id, notes)

    if success:
        return jsonify({'status': 'acknowledged', 'alert_id': alert_id})
    else:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404


# =============================================================================
# Cell Tower Database Endpoints
# =============================================================================

@gsm_bp.route('/nearby_towers')
def nearby_towers():
    """Query nearby towers from cell database."""
    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)
    radius = request.args.get('radius', default=50, type=float)
    radio = request.args.get('radio', default='LTE')
    limit = request.args.get('limit', default=100, type=int)

    if lat is None or lon is None:
        return jsonify({'status': 'error', 'message': 'lat and lon required'}), 400

    try:
        towers = get_nearby_towers(lat, lon, radius, radio, limit)
        return jsonify({
            'towers': towers,
            'count': len(towers),
            'query': {
                'lat': lat,
                'lon': lon,
                'radius_km': radius,
                'radio': radio
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@gsm_bp.route('/cell_database/stats')
def cell_database_stats():
    """Get cell tower database statistics."""
    try:
        stats = get_database_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@gsm_bp.route('/lookup_tower')
def lookup_tower():
    """Look up a specific tower by identifiers."""
    mcc = request.args.get('mcc', type=int)
    mnc = request.args.get('mnc', type=int)
    lac = request.args.get('lac', type=int)
    cell_id = request.args.get('cell_id', type=int)

    if None in (mcc, mnc, lac, cell_id):
        return jsonify({'status': 'error', 'message': 'mcc, mnc, lac, and cell_id required'}), 400

    tower = get_tower_by_id(mcc, mnc, lac, cell_id)

    if tower:
        return jsonify({'tower': tower, 'found': True})
    else:
        return jsonify({'tower': None, 'found': False})


# =============================================================================
# Dashboard
# =============================================================================

@gsm_bp.route('/dashboard')
def gsm_dashboard():
    """GSM SPY dashboard."""
    return render_template('gsm_dashboard.html')
