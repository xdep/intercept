"""
Region Detection for GSM SPY.

Auto-detects country/region via timezone/locale for automatic band selection.
"""

from __future__ import annotations

import locale
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger('intercept.gsm.region_detector')


@dataclass
class RegionInfo:
    """Information about detected region."""
    country_code: str
    country_name: str
    detection_method: str
    confidence: str  # 'high', 'medium', 'low'
    bands: list[int]


# Timezone to country code mapping
TIMEZONE_TO_COUNTRY = {
    # North America
    'America/New_York': 'US',
    'America/Chicago': 'US',
    'America/Denver': 'US',
    'America/Los_Angeles': 'US',
    'America/Phoenix': 'US',
    'America/Anchorage': 'US',
    'America/Toronto': 'CA',
    'America/Vancouver': 'CA',
    'America/Montreal': 'CA',
    'America/Mexico_City': 'MX',

    # Europe
    'Europe/London': 'GB',
    'Europe/Berlin': 'DE',
    'Europe/Paris': 'FR',
    'Europe/Rome': 'IT',
    'Europe/Madrid': 'ES',
    'Europe/Amsterdam': 'NL',
    'Europe/Brussels': 'BE',
    'Europe/Zurich': 'CH',
    'Europe/Vienna': 'AT',
    'Europe/Warsaw': 'PL',
    'Europe/Prague': 'CZ',
    'Europe/Budapest': 'HU',
    'Europe/Bucharest': 'RO',
    'Europe/Sofia': 'BG',
    'Europe/Athens': 'GR',
    'Europe/Lisbon': 'PT',
    'Europe/Copenhagen': 'DK',
    'Europe/Oslo': 'NO',
    'Europe/Stockholm': 'SE',
    'Europe/Helsinki': 'FI',
    'Europe/Dublin': 'IE',
    'Europe/Moscow': 'RU',
    'Europe/Kiev': 'UA',

    # Asia Pacific
    'Asia/Tokyo': 'JP',
    'Asia/Seoul': 'KR',
    'Asia/Shanghai': 'CN',
    'Asia/Hong_Kong': 'CN',
    'Asia/Taipei': 'TW',
    'Asia/Bangkok': 'TH',
    'Asia/Kuala_Lumpur': 'MY',
    'Asia/Singapore': 'SG',
    'Asia/Jakarta': 'ID',
    'Asia/Manila': 'PH',
    'Asia/Ho_Chi_Minh': 'VN',
    'Asia/Kolkata': 'IN',
    'Asia/Mumbai': 'IN',
    'Asia/Dhaka': 'BD',
    'Asia/Karachi': 'PK',

    # Oceania
    'Australia/Sydney': 'AU',
    'Australia/Melbourne': 'AU',
    'Australia/Brisbane': 'AU',
    'Australia/Perth': 'AU',
    'Pacific/Auckland': 'NZ',

    # Middle East
    'Asia/Riyadh': 'SA',
    'Asia/Dubai': 'AE',
    'Asia/Jerusalem': 'IL',

    # Africa
    'Africa/Cairo': 'EG',
    'Africa/Johannesburg': 'ZA',
    'Africa/Lagos': 'NG',
    'Africa/Nairobi': 'KE',

    # South America
    'America/Sao_Paulo': 'BR',
    'America/Buenos_Aires': 'AR',
    'America/Santiago': 'CL',
    'America/Bogota': 'CO',
    'America/Lima': 'PE',
    'America/Caracas': 'VE',
}

# Country code to name mapping
COUNTRY_NAMES = {
    'US': 'United States',
    'CA': 'Canada',
    'MX': 'Mexico',
    'GB': 'United Kingdom',
    'DE': 'Germany',
    'FR': 'France',
    'IT': 'Italy',
    'ES': 'Spain',
    'NL': 'Netherlands',
    'BE': 'Belgium',
    'CH': 'Switzerland',
    'AT': 'Austria',
    'PL': 'Poland',
    'CZ': 'Czech Republic',
    'HU': 'Hungary',
    'RO': 'Romania',
    'BG': 'Bulgaria',
    'GR': 'Greece',
    'PT': 'Portugal',
    'DK': 'Denmark',
    'NO': 'Norway',
    'SE': 'Sweden',
    'FI': 'Finland',
    'IE': 'Ireland',
    'RU': 'Russia',
    'UA': 'Ukraine',
    'JP': 'Japan',
    'KR': 'South Korea',
    'CN': 'China',
    'TW': 'Taiwan',
    'TH': 'Thailand',
    'MY': 'Malaysia',
    'SG': 'Singapore',
    'ID': 'Indonesia',
    'PH': 'Philippines',
    'VN': 'Vietnam',
    'IN': 'India',
    'BD': 'Bangladesh',
    'PK': 'Pakistan',
    'AU': 'Australia',
    'NZ': 'New Zealand',
    'SA': 'Saudi Arabia',
    'AE': 'United Arab Emirates',
    'IL': 'Israel',
    'EG': 'Egypt',
    'ZA': 'South Africa',
    'NG': 'Nigeria',
    'KE': 'Kenya',
    'BR': 'Brazil',
    'AR': 'Argentina',
    'CL': 'Chile',
    'CO': 'Colombia',
    'PE': 'Peru',
    'VE': 'Venezuela',
    'EU': 'Europe (Generic)',
}


def _detect_from_timezone() -> str | None:
    """Detect country from system timezone."""
    try:
        # Try reading /etc/timezone (Linux)
        tz_file = Path('/etc/timezone')
        if tz_file.exists():
            tz = tz_file.read_text().strip()
            if tz in TIMEZONE_TO_COUNTRY:
                return TIMEZONE_TO_COUNTRY[tz]

        # Try TZ environment variable
        tz = os.environ.get('TZ', '')
        if tz in TIMEZONE_TO_COUNTRY:
            return TIMEZONE_TO_COUNTRY[tz]

        # Try reading /etc/localtime symlink
        localtime = Path('/etc/localtime')
        if localtime.is_symlink():
            target = str(localtime.resolve())
            for tz, country in TIMEZONE_TO_COUNTRY.items():
                if tz in target:
                    return country

    except Exception as e:
        logger.debug(f"Timezone detection failed: {e}")

    return None


def _detect_from_locale() -> str | None:
    """Detect country from system locale."""
    try:
        # Get current locale
        loc = locale.getlocale()[0]
        if loc:
            # Locale format is typically 'en_US', 'de_DE', etc.
            parts = loc.split('_')
            if len(parts) >= 2:
                country = parts[1].upper()
                if country in COUNTRY_NAMES:
                    return country

        # Try LANG environment variable
        lang = os.environ.get('LANG', '')
        if '_' in lang:
            country = lang.split('_')[1][:2].upper()
            if country in COUNTRY_NAMES:
                return country

    except Exception as e:
        logger.debug(f"Locale detection failed: {e}")

    return None


def detect_region(manual_override: str | None = None) -> RegionInfo:
    """
    Detect the current region for band selection.

    Args:
        manual_override: Optional manual country code override

    Returns:
        RegionInfo with detected country and recommended bands
    """
    from data.gsm_bands import get_bands_for_country

    # Manual override takes precedence
    if manual_override:
        country = manual_override.upper()
        return RegionInfo(
            country_code=country,
            country_name=COUNTRY_NAMES.get(country, country),
            detection_method='manual',
            confidence='high',
            bands=get_bands_for_country(country)
        )

    # Try timezone detection first (more reliable)
    country = _detect_from_timezone()
    if country:
        return RegionInfo(
            country_code=country,
            country_name=COUNTRY_NAMES.get(country, country),
            detection_method='timezone',
            confidence='high',
            bands=get_bands_for_country(country)
        )

    # Try locale detection
    country = _detect_from_locale()
    if country:
        return RegionInfo(
            country_code=country,
            country_name=COUNTRY_NAMES.get(country, country),
            detection_method='locale',
            confidence='medium',
            bands=get_bands_for_country(country)
        )

    # Default to Europe if detection fails
    logger.warning("Region detection failed, defaulting to EU bands")
    return RegionInfo(
        country_code='EU',
        country_name='Europe (Default)',
        detection_method='default',
        confidence='low',
        bands=get_bands_for_country('EU')
    )


def get_scan_bands(
    region: str | None = None,
    bands_override: list[int] | None = None
) -> list[int]:
    """
    Get the list of LTE bands to scan.

    Args:
        region: Optional region code to use
        bands_override: Optional manual list of bands

    Returns:
        List of band numbers to scan
    """
    if bands_override:
        return bands_override

    region_info = detect_region(region)
    return region_info.bands


def get_available_regions() -> dict[str, str]:
    """Get all available regions with their names."""
    return COUNTRY_NAMES.copy()
