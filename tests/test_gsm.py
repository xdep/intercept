"""Tests for GSM SPY functionality."""

import pytest
from unittest.mock import patch, MagicMock

# Test timing advance calculations
class TestTimingAdvance:
    """Tests for timing advance distance calculations."""

    def test_gsm_ta_distance(self):
        """Test GSM timing advance to distance conversion."""
        from utils.gsm.timing_advance import (
            calculate_distance_from_ta,
            CellularTechnology,
        )

        # GSM TA = 0 should be ~0m
        result = calculate_distance_from_ta(0, CellularTechnology.GSM)
        assert result.center_distance_m == 0

        # GSM TA = 1 should be ~550m
        result = calculate_distance_from_ta(1, CellularTechnology.GSM)
        assert 500 <= result.center_distance_m <= 600

        # GSM TA = 63 (max) should be ~35km
        result = calculate_distance_from_ta(63, CellularTechnology.GSM)
        assert 34000 <= result.center_distance_m <= 36000

    def test_lte_ta_distance(self):
        """Test LTE timing advance to distance conversion."""
        from utils.gsm.timing_advance import (
            calculate_distance_from_ta,
            CellularTechnology,
        )

        # LTE TA = 0 should be ~0m
        result = calculate_distance_from_ta(0, CellularTechnology.LTE)
        assert result.center_distance_m == 0

        # LTE TA = 100 should be ~3.9km (round trip / 2)
        result = calculate_distance_from_ta(100, CellularTechnology.LTE)
        assert 3500 <= result.center_distance_m <= 4500

    def test_ta_ring_coordinates(self):
        """Test generating ring coordinates from TA."""
        from utils.gsm.timing_advance import ta_to_ring_coordinates

        # Generate a ring at 1km radius
        coords = ta_to_ring_coordinates(51.5074, -0.1278, 1000, num_points=8)

        # Should have 9 points (8 + closing point)
        assert len(coords) == 9

        # First and last should be the same (closed ring)
        assert coords[0] == coords[-1]

        # All points should be approximately 1km from center
        for lat, lon in coords[:-1]:
            assert 51.49 < lat < 51.52
            assert -0.15 < lon < -0.10


class TestRegionDetection:
    """Tests for region detection."""

    def test_detect_region_manual(self):
        """Test manual region override."""
        from utils.gsm.region_detector import detect_region

        result = detect_region('US')
        assert result.country_code == 'US'
        assert result.detection_method == 'manual'
        assert result.confidence == 'high'
        assert 2 in result.bands  # US uses band 2

    def test_detect_region_default(self):
        """Test default region when detection fails."""
        from utils.gsm.region_detector import detect_region

        # Without manual override and in a test environment, should default
        result = detect_region()
        assert result.country_code in ['EU', 'US', 'GB']  # Could detect or default


class TestBandData:
    """Tests for band data."""

    def test_earfcn_to_frequency(self):
        """Test EARFCN to frequency conversion."""
        from data.gsm_bands import earfcn_to_frequency

        # Band 1 EARFCN 100 should be around 2110 MHz
        result = earfcn_to_frequency(100)
        assert result is not None
        band, freq = result
        assert band == 1
        assert 2110 <= freq <= 2170

        # Band 3 EARFCN 1500 should be around 1835 MHz
        result = earfcn_to_frequency(1500)
        assert result is not None
        band, freq = result
        assert band == 3

    def test_get_bands_for_country(self):
        """Test getting bands for a country."""
        from data.gsm_bands import get_bands_for_country

        us_bands = get_bands_for_country('US')
        assert 2 in us_bands  # PCS
        assert 4 in us_bands  # AWS

        uk_bands = get_bands_for_country('GB')
        assert 20 in uk_bands  # 800 DD

    def test_mcc_to_country(self):
        """Test MCC to country mapping."""
        from data.gsm_bands import get_country_from_mcc

        assert get_country_from_mcc(310) == 'US'
        assert get_country_from_mcc(234) == 'GB'
        assert get_country_from_mcc(262) == 'DE'
        assert get_country_from_mcc(440) == 'JP'


class TestAlertEngine:
    """Tests for alert engine."""

    def test_stingray_score_strong_signal(self):
        """Test Stingray score for unusually strong signal."""
        from utils.gsm.alert_engine import AlertEngine

        engine = AlertEngine()

        # Tower with very strong signal
        tower = {
            'earfcn': 1500,
            'pci': 100,
            'rsrp': -60,  # Very strong (threshold is -70)
            'in_database': True,
        }

        score, evidence = engine.calculate_stingray_score(tower)
        assert score >= 25  # Should get points for strong signal
        assert 'strong_signal' in evidence

    def test_stingray_score_weak_encryption(self):
        """Test Stingray score for weak encryption."""
        from utils.gsm.alert_engine import AlertEngine

        engine = AlertEngine()

        # Tower with no encryption
        tower = {
            'earfcn': 1500,
            'pci': 100,
            'encryption': 'A5/0',
            'in_database': True,
        }

        score, evidence = engine.calculate_stingray_score(tower)
        assert score >= 25  # Should get points for weak encryption
        assert 'weak_encryption' in evidence

    def test_stingray_score_not_in_database(self):
        """Test Stingray score for unknown tower."""
        from utils.gsm.alert_engine import AlertEngine

        engine = AlertEngine()

        # Tower not in database
        tower = {
            'earfcn': 1500,
            'pci': 100,
            'in_database': False,
        }

        score, evidence = engine.calculate_stingray_score(tower)
        assert score >= 20  # Should get points for not being in DB
        assert 'not_in_database' in evidence

    def test_analyze_tower_generates_alerts(self):
        """Test that analyzing suspicious tower generates alerts."""
        from utils.gsm.alert_engine import AlertEngine, AlertSeverity

        engine = AlertEngine()

        # Very suspicious tower
        tower = {
            'earfcn': 1500,
            'pci': 100,
            'rsrp': -55,  # Very strong
            'encryption': 'A5/0',  # No encryption
            'in_database': False,
            'database_match_distance_km': 15,  # Location mismatch
        }

        alerts = engine.analyze_tower(tower)
        assert len(alerts) > 0

        # Should have high severity alert
        severities = [a.severity for a in alerts]
        assert AlertSeverity.HIGH in severities or AlertSeverity.CRITICAL in severities


class TestFingerprint:
    """Tests for RF fingerprinting."""

    def test_create_fingerprint(self):
        """Test creating a fingerprint."""
        from utils.gsm.fingerprint import create_fingerprint

        fp = create_fingerprint(
            pci=100,
            earfcn=1500,
            bandwidth_mhz=10.0,
            cp_type='Normal',
        )

        assert fp.pci == 100
        assert fp.earfcn == 1500
        assert fp.bandwidth_mhz == 10.0

    def test_fingerprint_hash(self):
        """Test fingerprint hash generation."""
        from utils.gsm.fingerprint import create_fingerprint, fingerprint_to_hash

        fp1 = create_fingerprint(pci=100, earfcn=1500)
        fp2 = create_fingerprint(pci=100, earfcn=1500)
        fp3 = create_fingerprint(pci=101, earfcn=1500)

        hash1 = fingerprint_to_hash(fp1)
        hash2 = fingerprint_to_hash(fp2)
        hash3 = fingerprint_to_hash(fp3)

        # Same parameters should give same hash
        assert hash1 == hash2

        # Different parameters should give different hash
        assert hash1 != hash3

    def test_compare_fingerprints(self):
        """Test fingerprint comparison."""
        from utils.gsm.fingerprint import create_fingerprint, compare_fingerprints

        fp1 = create_fingerprint(pci=100, earfcn=1500, bandwidth_mhz=10.0)
        fp2 = create_fingerprint(pci=100, earfcn=1500, bandwidth_mhz=10.0)
        fp3 = create_fingerprint(pci=100, earfcn=1600, bandwidth_mhz=10.0)

        # Same fingerprints should have high similarity
        assert compare_fingerprints(fp1, fp2) >= 0.9

        # Different EARFCN should have lower similarity
        assert compare_fingerprints(fp1, fp3) < 0.7


class TestSrsRANWrapper:
    """Tests for srsRAN wrapper."""

    def test_find_srsran_binary(self):
        """Test finding srsRAN binary."""
        from utils.gsm.srsran_wrapper import find_srsran_cell_search

        # May or may not find it depending on installation
        path = find_srsran_cell_search()
        # Just verify it doesn't crash
        assert path is None or isinstance(path, str)

    def test_cell_search_result_dataclass(self):
        """Test CellSearchResult dataclass."""
        from utils.gsm.srsran_wrapper import CellSearchResult

        result = CellSearchResult(
            earfcn=1500,
            pci=100,
            frequency_mhz=1835.0,
            band=3,
            rsrp=-80.0,
        )

        assert result.earfcn == 1500
        assert result.pci == 100

        # Test to_dict
        d = result.to_dict()
        assert d['earfcn'] == 1500
        assert d['pci'] == 100


class TestCellDatabase:
    """Tests for cell tower database."""

    def test_init_cell_db(self):
        """Test initializing cell database."""
        from utils.gsm.cell_database import init_cell_db, get_cell_db_path

        # Should not raise
        init_cell_db()

        # Database file should exist
        db_path = get_cell_db_path()
        assert db_path.parent.exists()

    def test_haversine_distance(self):
        """Test haversine distance calculation."""
        from utils.gsm.cell_database import _haversine_distance

        # London to Paris is about 344 km
        london = (51.5074, -0.1278)
        paris = (48.8566, 2.3522)

        dist = _haversine_distance(*london, *paris)
        assert 340 < dist < 350


class TestDatabaseFunctions:
    """Tests for database CRUD functions."""

    def test_create_gsm_session(self):
        """Test creating a GSM session."""
        from utils.database import create_gsm_session, get_gsm_session, init_db

        init_db()

        session_id = create_gsm_session(
            device_index=0,
            gain=40.0,
            region='US',
            bands=[2, 4, 12],
        )

        assert session_id is not None
        assert session_id > 0

        # Retrieve session
        session = get_gsm_session(session_id)
        assert session is not None
        assert session['region'] == 'US'
        assert 2 in session['bands']

    def test_add_gsm_tower(self):
        """Test adding a GSM tower."""
        from utils.database import create_gsm_session, add_gsm_tower, get_gsm_towers, init_db

        init_db()

        session_id = create_gsm_session()

        tower_id = add_gsm_tower(
            session_id=session_id,
            earfcn=1500,
            pci=100,
            frequency_mhz=1835.0,
            rsrp=-80.0,
            stingray_score=25,
        )

        assert tower_id is not None

        # Retrieve towers
        towers = get_gsm_towers(session_id=session_id)
        assert len(towers) >= 1

    def test_add_gsm_alert(self):
        """Test adding a GSM alert."""
        from utils.database import create_gsm_session, add_gsm_alert, get_gsm_alerts, init_db

        init_db()

        session_id = create_gsm_session()

        alert_id = add_gsm_alert(
            session_id=session_id,
            alert_type='STINGRAY',
            severity='HIGH',
            title='Test Alert',
            description='Test description',
            score=75,
        )

        assert alert_id is not None

        # Retrieve alerts
        alerts = get_gsm_alerts(session_id=session_id)
        assert len(alerts) >= 1
        assert alerts[0]['alert_type'] == 'STINGRAY'
