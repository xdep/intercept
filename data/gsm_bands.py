"""
GSM/LTE Band Definitions and Regional Configurations.

Provides MCC-to-country mappings, LTE band definitions with EARFCN ranges,
and regional band configurations for different countries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple


# =============================================================================
# MCC to Country Code Mapping
# =============================================================================

MCC_TO_COUNTRY = {
    # North America
    310: 'US', 311: 'US', 312: 'US', 313: 'US', 314: 'US', 315: 'US', 316: 'US',
    302: 'CA',  # Canada
    334: 'MX',  # Mexico

    # Europe
    234: 'GB', 235: 'GB',  # United Kingdom
    262: 'DE',  # Germany
    208: 'FR',  # France
    222: 'IT',  # Italy
    214: 'ES',  # Spain
    204: 'NL',  # Netherlands
    206: 'BE',  # Belgium
    228: 'CH',  # Switzerland
    232: 'AT',  # Austria
    260: 'PL',  # Poland
    230: 'CZ',  # Czech Republic
    216: 'HU',  # Hungary
    226: 'RO',  # Romania
    284: 'BG',  # Bulgaria
    202: 'GR',  # Greece
    268: 'PT',  # Portugal
    238: 'DK',  # Denmark
    242: 'NO',  # Norway
    240: 'SE',  # Sweden
    244: 'FI',  # Finland
    272: 'IE',  # Ireland
    250: 'RU',  # Russia
    255: 'UA',  # Ukraine

    # Asia Pacific
    440: 'JP', 441: 'JP',  # Japan
    450: 'KR',  # South Korea
    460: 'CN',  # China
    466: 'TW',  # Taiwan
    520: 'TH',  # Thailand
    502: 'MY',  # Malaysia
    525: 'SG',  # Singapore
    510: 'ID',  # Indonesia
    515: 'PH',  # Philippines
    452: 'VN',  # Vietnam
    404: 'IN', 405: 'IN', 406: 'IN',  # India
    470: 'BD',  # Bangladesh
    410: 'PK',  # Pakistan

    # Oceania
    505: 'AU',  # Australia
    530: 'NZ',  # New Zealand

    # Middle East & Africa
    420: 'SA',  # Saudi Arabia
    424: 'AE',  # UAE
    425: 'IL',  # Israel
    602: 'EG',  # Egypt
    655: 'ZA',  # South Africa
    621: 'NG',  # Nigeria
    639: 'KE',  # Kenya

    # South America
    724: 'BR',  # Brazil
    722: 'AR',  # Argentina
    730: 'CL',  # Chile
    732: 'CO',  # Colombia
    716: 'PE',  # Peru
    734: 'VE',  # Venezuela
}


def get_country_from_mcc(mcc: int) -> str | None:
    """Get ISO country code from MCC."""
    return MCC_TO_COUNTRY.get(mcc)


# =============================================================================
# LTE Band Definitions
# =============================================================================

@dataclass
class LTEBand:
    """LTE frequency band definition."""
    band: int
    name: str
    mode: str  # FDD or TDD
    uplink_low_mhz: float
    uplink_high_mhz: float
    downlink_low_mhz: float
    downlink_high_mhz: float
    earfcn_offset: int  # EARFCN offset for downlink
    earfcn_range: tuple[int, int]  # (min, max) EARFCN
    common_name: str | None = None


# LTE FDD Bands
LTE_BANDS = {
    1: LTEBand(1, 'Band 1', 'FDD', 1920, 1980, 2110, 2170, 0, (0, 599), '2100 MHz IMT'),
    2: LTEBand(2, 'Band 2', 'FDD', 1850, 1910, 1930, 1990, 600, (600, 1199), '1900 MHz PCS'),
    3: LTEBand(3, 'Band 3', 'FDD', 1710, 1785, 1805, 1880, 1200, (1200, 1949), '1800 MHz DCS'),
    4: LTEBand(4, 'Band 4', 'FDD', 1710, 1755, 2110, 2155, 1950, (1950, 2399), 'AWS-1'),
    5: LTEBand(5, 'Band 5', 'FDD', 824, 849, 869, 894, 2400, (2400, 2649), '850 MHz CLR'),
    7: LTEBand(7, 'Band 7', 'FDD', 2500, 2570, 2620, 2690, 2750, (2750, 3449), '2600 MHz IMT-E'),
    8: LTEBand(8, 'Band 8', 'FDD', 880, 915, 925, 960, 3450, (3450, 3799), '900 MHz E-GSM'),
    12: LTEBand(12, 'Band 12', 'FDD', 699, 716, 729, 746, 5010, (5010, 5179), '700 MHz Lower'),
    13: LTEBand(13, 'Band 13', 'FDD', 777, 787, 746, 756, 5180, (5180, 5279), '700 MHz Upper C'),
    14: LTEBand(14, 'Band 14', 'FDD', 788, 798, 758, 768, 5280, (5280, 5379), '700 MHz PS'),
    17: LTEBand(17, 'Band 17', 'FDD', 704, 716, 734, 746, 5730, (5730, 5849), '700 MHz Lower BC'),
    18: LTEBand(18, 'Band 18', 'FDD', 815, 830, 860, 875, 5850, (5850, 5999), '800 MHz Lower'),
    19: LTEBand(19, 'Band 19', 'FDD', 830, 845, 875, 890, 6000, (6000, 6149), '800 MHz Upper'),
    20: LTEBand(20, 'Band 20', 'FDD', 832, 862, 791, 821, 6150, (6150, 6449), '800 MHz DD'),
    21: LTEBand(21, 'Band 21', 'FDD', 1447.9, 1462.9, 1495.9, 1510.9, 6450, (6450, 6599), '1500 MHz Lower'),
    25: LTEBand(25, 'Band 25', 'FDD', 1850, 1915, 1930, 1995, 8040, (8040, 8689), '1900 MHz Extended'),
    26: LTEBand(26, 'Band 26', 'FDD', 814, 849, 859, 894, 8690, (8690, 9039), '850 MHz Extended'),
    28: LTEBand(28, 'Band 28', 'FDD', 703, 748, 758, 803, 9210, (9210, 9659), '700 MHz APT'),
    29: LTEBand(29, 'Band 29', 'FDD', 0, 0, 717, 728, 9660, (9660, 9769), '700 MHz SDL'),
    30: LTEBand(30, 'Band 30', 'FDD', 2305, 2315, 2350, 2360, 9770, (9770, 9869), '2300 MHz WCS'),
    31: LTEBand(31, 'Band 31', 'FDD', 452.5, 457.5, 462.5, 467.5, 9870, (9870, 9919), '450 MHz'),
    32: LTEBand(32, 'Band 32', 'FDD', 0, 0, 1452, 1496, 9920, (9920, 10359), '1500 MHz SDL'),
    66: LTEBand(66, 'Band 66', 'FDD', 1710, 1780, 2110, 2200, 66436, (66436, 67335), 'AWS-3'),
    71: LTEBand(71, 'Band 71', 'FDD', 663, 698, 617, 652, 68586, (68586, 68935), '600 MHz'),

    # LTE TDD Bands
    33: LTEBand(33, 'Band 33', 'TDD', 1900, 1920, 1900, 1920, 36000, (36000, 36199), 'TD 1900'),
    34: LTEBand(34, 'Band 34', 'TDD', 2010, 2025, 2010, 2025, 36200, (36200, 36349), 'TD 2000'),
    35: LTEBand(35, 'Band 35', 'TDD', 1850, 1910, 1850, 1910, 36350, (36350, 36949), 'TD PCS Lower'),
    36: LTEBand(36, 'Band 36', 'TDD', 1930, 1990, 1930, 1990, 36950, (36950, 37549), 'TD PCS Upper'),
    37: LTEBand(37, 'Band 37', 'TDD', 1910, 1930, 1910, 1930, 37550, (37550, 37749), 'TD PCS Center'),
    38: LTEBand(38, 'Band 38', 'TDD', 2570, 2620, 2570, 2620, 37750, (37750, 38249), 'TD 2600'),
    39: LTEBand(39, 'Band 39', 'TDD', 1880, 1920, 1880, 1920, 38250, (38250, 38649), 'TD 1900+'),
    40: LTEBand(40, 'Band 40', 'TDD', 2300, 2400, 2300, 2400, 38650, (38650, 39649), 'TD 2300'),
    41: LTEBand(41, 'Band 41', 'TDD', 2496, 2690, 2496, 2690, 39650, (39650, 41589), 'TD 2500'),
    42: LTEBand(42, 'Band 42', 'TDD', 3400, 3600, 3400, 3600, 41590, (41590, 43589), '3500 MHz'),
    43: LTEBand(43, 'Band 43', 'TDD', 3600, 3800, 3600, 3800, 43590, (43590, 45589), '3700 MHz'),
    44: LTEBand(44, 'Band 44', 'TDD', 703, 803, 703, 803, 45590, (45590, 46589), 'TD 700'),
    48: LTEBand(48, 'Band 48', 'TDD', 3550, 3700, 3550, 3700, 55240, (55240, 56739), 'CBRS'),
}


def get_band(band_number: int) -> LTEBand | None:
    """Get LTE band definition by band number."""
    return LTE_BANDS.get(band_number)


def earfcn_to_frequency(earfcn: int) -> tuple[int, float] | None:
    """
    Convert EARFCN to frequency in MHz.

    Returns:
        Tuple of (band_number, frequency_mhz) or None if not found
    """
    for band_num, band in LTE_BANDS.items():
        if band.earfcn_range[0] <= earfcn <= band.earfcn_range[1]:
            # Calculate frequency
            offset = earfcn - band.earfcn_offset
            freq_mhz = band.downlink_low_mhz + (offset * 0.1)
            return (band_num, freq_mhz)
    return None


def frequency_to_earfcn(freq_mhz: float, band_number: int) -> int | None:
    """
    Convert frequency to EARFCN for a specific band.

    Returns:
        EARFCN value or None if frequency not in band
    """
    band = LTE_BANDS.get(band_number)
    if not band:
        return None

    if not (band.downlink_low_mhz <= freq_mhz <= band.downlink_high_mhz):
        return None

    earfcn = band.earfcn_offset + int((freq_mhz - band.downlink_low_mhz) * 10)
    return earfcn


def get_earfcn_range_for_band(band_number: int) -> tuple[int, int] | None:
    """Get the EARFCN range for a band."""
    band = LTE_BANDS.get(band_number)
    return band.earfcn_range if band else None


# =============================================================================
# Regional Band Configurations
# =============================================================================

# Common bands used in each region
REGIONAL_BANDS = {
    # North America
    'US': [2, 4, 5, 12, 13, 14, 17, 25, 26, 30, 66, 71, 41, 48],
    'CA': [2, 4, 5, 7, 12, 13, 17, 29, 66, 71],
    'MX': [2, 4, 5, 7, 28],

    # Europe
    'GB': [1, 3, 7, 8, 20, 28, 32, 38, 40],
    'DE': [1, 3, 7, 8, 20, 28, 32, 38],
    'FR': [1, 3, 7, 20, 28, 32, 38],
    'IT': [1, 3, 7, 20, 28, 32, 38],
    'ES': [1, 3, 7, 20, 28, 38],
    'NL': [1, 3, 7, 20, 28, 38],
    'EU': [1, 3, 7, 8, 20, 28, 32, 38, 40],  # Generic Europe

    # Asia Pacific
    'JP': [1, 3, 8, 11, 18, 19, 21, 26, 28, 41, 42],
    'KR': [1, 3, 5, 7, 8, 26, 38, 40, 41],
    'CN': [1, 3, 5, 7, 8, 34, 38, 39, 40, 41],
    'TW': [1, 3, 7, 8, 28, 38],
    'SG': [1, 3, 7, 8, 28, 40],
    'AU': [1, 3, 5, 7, 8, 28, 40, 42],
    'NZ': [1, 3, 7, 8, 28, 40],
    'IN': [1, 3, 5, 8, 40, 41],
    'TH': [1, 3, 5, 7, 8, 28, 40, 41],

    # Middle East
    'AE': [1, 3, 7, 20, 38, 40, 41],
    'SA': [1, 3, 7, 8, 20, 38, 40, 41],

    # Africa
    'ZA': [1, 3, 7, 8, 20, 28, 38, 40, 41],

    # South America
    'BR': [1, 3, 7, 28, 38, 40, 41],
    'AR': [2, 4, 7, 28],
    'CL': [2, 4, 7, 28, 38],
}


def get_bands_for_country(country_code: str) -> list[int]:
    """
    Get common LTE bands for a country.

    Args:
        country_code: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')

    Returns:
        List of band numbers commonly used in that country
    """
    country_code = country_code.upper()
    return REGIONAL_BANDS.get(country_code, REGIONAL_BANDS.get('EU', [1, 3, 7, 20]))


def get_region_from_mcc(mcc: int) -> str:
    """
    Get region code from MCC.

    Returns country code or 'EU' as default.
    """
    return MCC_TO_COUNTRY.get(mcc, 'EU')


def get_bands_for_mcc(mcc: int) -> list[int]:
    """Get common LTE bands based on MCC."""
    country = get_country_from_mcc(mcc)
    if country:
        return get_bands_for_country(country)
    return REGIONAL_BANDS.get('EU', [1, 3, 7, 20])


# =============================================================================
# Carrier Information (Major carriers by country)
# =============================================================================

CARRIER_INFO = {
    # US
    ('310', '260'): {'name': 'T-Mobile US', 'country': 'US'},
    ('310', '410'): {'name': 'AT&T', 'country': 'US'},
    ('311', '480'): {'name': 'Verizon', 'country': 'US'},
    ('312', '530'): {'name': 'Sprint', 'country': 'US'},

    # UK
    ('234', '10'): {'name': 'O2 UK', 'country': 'GB'},
    ('234', '15'): {'name': 'Vodafone UK', 'country': 'GB'},
    ('234', '20'): {'name': 'Three UK', 'country': 'GB'},
    ('234', '30'): {'name': 'EE', 'country': 'GB'},

    # Germany
    ('262', '01'): {'name': 'Telekom DE', 'country': 'DE'},
    ('262', '02'): {'name': 'Vodafone DE', 'country': 'DE'},
    ('262', '03'): {'name': 'O2 DE', 'country': 'DE'},

    # France
    ('208', '01'): {'name': 'Orange FR', 'country': 'FR'},
    ('208', '10'): {'name': 'SFR', 'country': 'FR'},
    ('208', '20'): {'name': 'Bouygues', 'country': 'FR'},
    ('208', '15'): {'name': 'Free Mobile', 'country': 'FR'},

    # Japan
    ('440', '10'): {'name': 'NTT Docomo', 'country': 'JP'},
    ('440', '20'): {'name': 'SoftBank', 'country': 'JP'},
    ('441', '10'): {'name': 'au (KDDI)', 'country': 'JP'},

    # South Korea
    ('450', '05'): {'name': 'SK Telecom', 'country': 'KR'},
    ('450', '06'): {'name': 'LG U+', 'country': 'KR'},
    ('450', '08'): {'name': 'KT', 'country': 'KR'},

    # China
    ('460', '00'): {'name': 'China Mobile', 'country': 'CN'},
    ('460', '01'): {'name': 'China Unicom', 'country': 'CN'},
    ('460', '03'): {'name': 'China Telecom', 'country': 'CN'},

    # Australia
    ('505', '01'): {'name': 'Telstra', 'country': 'AU'},
    ('505', '02'): {'name': 'Optus', 'country': 'AU'},
    ('505', '03'): {'name': 'Vodafone AU', 'country': 'AU'},
}


def get_carrier_info(mcc: int, mnc: int) -> dict | None:
    """
    Get carrier information from MCC/MNC.

    Returns:
        Dict with 'name' and 'country' or None if not found
    """
    # Try with zero-padded MNC
    key = (str(mcc), str(mnc).zfill(2))
    if key in CARRIER_INFO:
        return CARRIER_INFO[key]

    # Try without padding
    key = (str(mcc), str(mnc))
    return CARRIER_INFO.get(key)


# =============================================================================
# Encryption Types
# =============================================================================

ENCRYPTION_TYPES = {
    'A5/0': {'name': 'No encryption', 'strength': 'NONE', 'warning': True},
    'A5/1': {'name': 'A5/1 (Weak)', 'strength': 'WEAK', 'warning': True},
    'A5/2': {'name': 'A5/2 (Broken)', 'strength': 'BROKEN', 'warning': True},
    'A5/3': {'name': 'A5/3 (KASUMI)', 'strength': 'MODERATE', 'warning': False},
    'A5/4': {'name': 'A5/4 (128-bit)', 'strength': 'STRONG', 'warning': False},
    'GEA0': {'name': 'No GPRS encryption', 'strength': 'NONE', 'warning': True},
    'GEA1': {'name': 'GEA1 (Weak)', 'strength': 'WEAK', 'warning': True},
    'GEA2': {'name': 'GEA2', 'strength': 'MODERATE', 'warning': False},
    'GEA3': {'name': 'GEA3 (KASUMI)', 'strength': 'MODERATE', 'warning': False},
    'EEA0': {'name': 'EPS Null', 'strength': 'NONE', 'warning': True},
    'EEA1': {'name': 'EPS AES-128', 'strength': 'STRONG', 'warning': False},
    'EEA2': {'name': 'EPS SNOW 3G', 'strength': 'STRONG', 'warning': False},
    'EEA3': {'name': 'EPS ZUC', 'strength': 'STRONG', 'warning': False},
}


def get_encryption_info(encryption_type: str) -> dict | None:
    """Get information about an encryption type."""
    return ENCRYPTION_TYPES.get(encryption_type.upper())


def is_weak_encryption(encryption_type: str) -> bool:
    """Check if encryption type is considered weak or vulnerable."""
    info = get_encryption_info(encryption_type)
    return info.get('warning', False) if info else False
