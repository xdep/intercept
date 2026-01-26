"""
Alert Engine for GSM SPY.

Detects security anomalies including:
- IMSI catchers (Stingrays)
- Encryption downgrades
- Rogue towers
- Silent SMS (Type 0)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from utils.constants import (
    STINGRAY_RSRP_THRESHOLD,
    STINGRAY_SCORE_WARNING,
    STINGRAY_SCORE_CRITICAL,
)

logger = logging.getLogger('intercept.gsm.alert_engine')


class AlertType(Enum):
    """Types of security alerts."""
    STINGRAY = 'STINGRAY'
    ENCRYPTION_DOWNGRADE = 'ENCRYPTION_DOWNGRADE'
    ROGUE_TOWER = 'ROGUE_TOWER'
    SILENT_SMS = 'SILENT_SMS'
    UNKNOWN_TOWER = 'UNKNOWN_TOWER'
    LOCATION_MISMATCH = 'LOCATION_MISMATCH'
    SIGNAL_ANOMALY = 'SIGNAL_ANOMALY'
    TRACKING_ATTEMPT = 'TRACKING_ATTEMPT'


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


@dataclass
class GSMAlert:
    """A GSM security alert."""
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    score: int = 0
    tower_data: dict | None = None
    client_data: dict | None = None
    evidence: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'score': self.score,
            'tower_data': self.tower_data,
            'client_data': self.client_data,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat(),
        }


class AlertEngine:
    """Engine for analyzing cell data and generating security alerts."""

    def __init__(self, nearby_towers_func=None):
        """
        Initialize alert engine.

        Args:
            nearby_towers_func: Function to query nearby towers from database
                               signature: (lat, lon, radius_km) -> list[dict]
        """
        self.nearby_towers_func = nearby_towers_func
        self.seen_towers = {}  # Track towers we've analyzed
        self.alerts = []

    def analyze_tower(
        self,
        tower_data: dict,
        observer_lat: float | None = None,
        observer_lon: float | None = None
    ) -> list[GSMAlert]:
        """
        Analyze a detected tower for security anomalies.

        Args:
            tower_data: Dictionary with tower information
            observer_lat: Observer latitude for distance checks
            observer_lon: Observer longitude for distance checks

        Returns:
            List of generated alerts
        """
        alerts = []

        # Calculate Stingray score
        stingray_score, stingray_evidence = self.calculate_stingray_score(
            tower_data, observer_lat, observer_lon
        )

        # Update tower data with score
        tower_data['stingray_score'] = stingray_score

        # Generate alerts based on score
        if stingray_score >= STINGRAY_SCORE_CRITICAL:
            alerts.append(GSMAlert(
                alert_type=AlertType.STINGRAY,
                severity=AlertSeverity.CRITICAL,
                title='IMSI Catcher Detected',
                description=f"High probability IMSI catcher (Stingray) detected. Score: {stingray_score}/100",
                score=stingray_score,
                tower_data=tower_data,
                evidence=stingray_evidence
            ))
        elif stingray_score >= STINGRAY_SCORE_WARNING:
            alerts.append(GSMAlert(
                alert_type=AlertType.STINGRAY,
                severity=AlertSeverity.HIGH,
                title='Suspicious Cell Tower',
                description=f"Tower exhibits suspicious characteristics. Score: {stingray_score}/100",
                score=stingray_score,
                tower_data=tower_data,
                evidence=stingray_evidence
            ))

        # Check for encryption issues
        encryption = tower_data.get('encryption', '')
        if encryption:
            enc_alert = self._check_encryption(encryption, tower_data)
            if enc_alert:
                alerts.append(enc_alert)

        # Check if tower is in database
        if not tower_data.get('in_database', False):
            alerts.append(GSMAlert(
                alert_type=AlertType.UNKNOWN_TOWER,
                severity=AlertSeverity.MEDIUM,
                title='Unknown Cell Tower',
                description='Cell tower not found in OpenCellID database',
                tower_data=tower_data,
                evidence={'reason': 'not_in_database'}
            ))

        # Check location mismatch
        if tower_data.get('database_match_distance_km') and tower_data['database_match_distance_km'] > 5:
            alerts.append(GSMAlert(
                alert_type=AlertType.LOCATION_MISMATCH,
                severity=AlertSeverity.HIGH,
                title='Tower Location Mismatch',
                description=f"Tower position differs {tower_data['database_match_distance_km']:.1f}km from database",
                tower_data=tower_data,
                evidence={'distance_km': tower_data['database_match_distance_km']}
            ))

        self.alerts.extend(alerts)
        return alerts

    def calculate_stingray_score(
        self,
        tower_data: dict,
        observer_lat: float | None = None,
        observer_lon: float | None = None
    ) -> tuple[int, dict]:
        """
        Calculate Stingray probability score (0-100).

        Higher scores indicate higher probability of IMSI catcher.

        Scoring factors:
        - Unusually strong signal (RSRP > -70 dBm): +25 points
        - Weak/no encryption (A5/0, A5/1, EEA0): +25 points
        - Not in cell tower database: +20 points
        - Location mismatch from database: +15 points
        - Unusual bandwidth for region: +5 points
        - No neighboring cells detected: +10 points

        Args:
            tower_data: Tower information dictionary
            observer_lat: Observer latitude
            observer_lon: Observer longitude

        Returns:
            Tuple of (score, evidence_dict)
        """
        score = 0
        evidence = {}

        # 1. Signal strength check
        rsrp = tower_data.get('rsrp')
        if rsrp is not None:
            if rsrp > STINGRAY_RSRP_THRESHOLD:
                score += 25
                evidence['strong_signal'] = {
                    'rsrp': rsrp,
                    'threshold': STINGRAY_RSRP_THRESHOLD,
                    'points': 25
                }
            elif rsrp > STINGRAY_RSRP_THRESHOLD - 10:
                score += 10
                evidence['strong_signal'] = {
                    'rsrp': rsrp,
                    'threshold': STINGRAY_RSRP_THRESHOLD,
                    'points': 10
                }

        # 2. Encryption check
        encryption = tower_data.get('encryption', '').upper()
        weak_encryptions = ['A5/0', 'A5/1', 'A5/2', 'GEA0', 'GEA1', 'EEA0']
        if encryption in weak_encryptions:
            score += 25
            evidence['weak_encryption'] = {
                'type': encryption,
                'points': 25
            }
        elif encryption == '' and tower_data.get('mib_data'):
            # Has MIB but no encryption info might indicate null cipher
            score += 10
            evidence['unknown_encryption'] = {
                'points': 10
            }

        # 3. Database presence check
        if not tower_data.get('in_database', False):
            score += 20
            evidence['not_in_database'] = {'points': 20}

        # 4. Location mismatch check
        distance_km = tower_data.get('database_match_distance_km')
        if distance_km is not None:
            if distance_km > 10:
                score += 15
                evidence['location_mismatch'] = {
                    'distance_km': distance_km,
                    'points': 15
                }
            elif distance_km > 5:
                score += 8
                evidence['location_mismatch'] = {
                    'distance_km': distance_km,
                    'points': 8
                }

        # 5. Check if tower appeared suddenly (new in this session)
        pci = tower_data.get('pci')
        earfcn = tower_data.get('earfcn')
        tower_key = f"{earfcn}_{pci}"

        if tower_key not in self.seen_towers:
            self.seen_towers[tower_key] = tower_data
        else:
            # Tower seen before - check for changes
            prev = self.seen_towers[tower_key]
            if prev.get('mcc') != tower_data.get('mcc') or prev.get('mnc') != tower_data.get('mnc'):
                score += 10
                evidence['identity_change'] = {
                    'prev_mcc': prev.get('mcc'),
                    'prev_mnc': prev.get('mnc'),
                    'new_mcc': tower_data.get('mcc'),
                    'new_mnc': tower_data.get('mnc'),
                    'points': 10
                }

        # 6. SNR anomaly check (Stingrays often have very clean signals)
        snr = tower_data.get('snr')
        if snr is not None and snr > 30:
            score += 5
            evidence['high_snr'] = {
                'snr': snr,
                'points': 5
            }

        # Cap at 100
        score = min(100, score)

        return score, evidence

    def detect_silent_sms(self, sms_data: dict) -> GSMAlert | None:
        """
        Detect silent (Type 0) SMS messages.

        Silent SMS are used by law enforcement and attackers to:
        - Ping a device to confirm it's active
        - Trigger location updates
        - Confirm IMSI association

        Args:
            sms_data: SMS message data

        Returns:
            GSMAlert if silent SMS detected, None otherwise
        """
        # Type 0 SMS has TP-PID = 0x40 (Short Message Type 0)
        tp_pid = sms_data.get('tp_pid', 0)
        tp_dcs = sms_data.get('tp_dcs', 0)

        is_silent = False
        evidence = {}

        # Check for Type 0 indicator
        if tp_pid == 0x40:
            is_silent = True
            evidence['type'] = 'Type 0 SMS (TP-PID=0x40)'

        # Check for Class 0 flash SMS with empty content (also suspicious)
        if (tp_dcs & 0xF3) == 0xF0 and not sms_data.get('content'):
            is_silent = True
            evidence['type'] = 'Class 0 Flash SMS (empty)'

        # Check for MWIS (Message Waiting Indication) with no message
        if (tp_dcs & 0xC0) == 0xC0:
            is_silent = True
            evidence['type'] = 'MWIS indicator'

        if is_silent:
            return GSMAlert(
                alert_type=AlertType.SILENT_SMS,
                severity=AlertSeverity.HIGH,
                title='Silent SMS Detected',
                description='A silent (Type 0) SMS was detected. This is often used for tracking.',
                client_data=sms_data,
                evidence=evidence
            )

        return None

    def _check_encryption(self, encryption: str, tower_data: dict) -> GSMAlert | None:
        """Check for weak encryption and generate alert."""
        from data.gsm_bands import is_weak_encryption, get_encryption_info

        if is_weak_encryption(encryption):
            info = get_encryption_info(encryption)
            severity = AlertSeverity.CRITICAL if info and info['strength'] == 'NONE' else AlertSeverity.HIGH

            return GSMAlert(
                alert_type=AlertType.ENCRYPTION_DOWNGRADE,
                severity=severity,
                title='Weak Cell Encryption',
                description=f"Tower using weak encryption: {encryption}",
                tower_data=tower_data,
                evidence={
                    'encryption': encryption,
                    'info': info
                }
            )

        return None

    def get_alerts(
        self,
        severity: AlertSeverity | None = None,
        alert_type: AlertType | None = None
    ) -> list[GSMAlert]:
        """Get alerts with optional filtering."""
        alerts = self.alerts

        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]

        return alerts

    def clear_alerts(self) -> None:
        """Clear all alerts."""
        self.alerts = []


# Privacy warning text for research mode
PRIVACY_WARNING = """
**WARNING: Research Mode Enabled**

This mode enables capture of International Mobile Subscriber Identity (IMSI) and Temporary Mobile Subscriber Identity (TMSI) data.

**Legal Notice**: Capturing IMSI data may be illegal in your jurisdiction without proper authorization. This feature is intended ONLY for:
- Authorized security research
- Law enforcement with proper warrants
- Network operators testing their own infrastructure
- Controlled laboratory environments

By enabling this mode, you acknowledge that you have proper legal authorization to capture this data.
"""


def get_privacy_warning() -> str:
    """Get the privacy warning text for research mode."""
    return PRIVACY_WARNING
