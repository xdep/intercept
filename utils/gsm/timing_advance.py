"""
Timing Advance Distance Calculator for GSM SPY.

Calculates distance estimates from timing advance values for different
cellular technologies (GSM, UMTS, LTE, NR).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple


class CellularTechnology(Enum):
    """Cellular technology types."""
    GSM = 'GSM'
    UMTS = 'UMTS'
    LTE = 'LTE'
    LTE_FINE = 'LTE_FINE'  # LTE with fine timing
    NR = 'NR'  # 5G NR


@dataclass
class DistanceEstimate:
    """Distance estimate from timing advance."""
    min_distance_m: float
    max_distance_m: float
    center_distance_m: float
    technology: CellularTechnology
    timing_advance: int
    resolution_m: float


# Timing advance resolution by technology
TA_RESOLUTION = {
    CellularTechnology.GSM: 550.0,      # ~550m per TA unit (1 bit period at GSM symbol rate)
    CellularTechnology.UMTS: 78.12,     # ~78m per chip (1/16 chip resolution)
    CellularTechnology.LTE: 78.12,      # ~78m per Ts (16 Ts per TA unit)
    CellularTechnology.LTE_FINE: 4.89,  # ~4.89m (fine resolution with extended TA)
    CellularTechnology.NR: 4.89,        # Similar to LTE fine (depends on numerology)
}

# Maximum TA values
MAX_TA_VALUE = {
    CellularTechnology.GSM: 63,         # 6-bit TA (0-63)
    CellularTechnology.UMTS: 1282,      # Round trip propagation delay max
    CellularTechnology.LTE: 1282,       # 11-bit TA (0-1282)
    CellularTechnology.LTE_FINE: 1282,  # Same range, finer resolution
    CellularTechnology.NR: 3846,        # Extended range for 5G
}


def calculate_distance_from_ta(
    ta_value: int,
    technology: CellularTechnology = CellularTechnology.LTE
) -> DistanceEstimate:
    """
    Calculate distance estimate from timing advance value.

    The timing advance is a round-trip measurement, so actual distance
    is half the propagation distance.

    Args:
        ta_value: Timing advance value from network
        technology: Cellular technology type

    Returns:
        DistanceEstimate with min/max/center distance in meters
    """
    if ta_value < 0:
        ta_value = 0

    max_ta = MAX_TA_VALUE.get(technology, 1282)
    if ta_value > max_ta:
        ta_value = max_ta

    resolution = TA_RESOLUTION.get(technology, 78.12)

    # For GSM, TA directly maps to distance
    # For LTE/UMTS, TA is round-trip so divide by 2
    if technology == CellularTechnology.GSM:
        # GSM TA is already one-way
        center_distance = ta_value * resolution
        min_distance = max(0, center_distance - resolution / 2)
        max_distance = center_distance + resolution / 2
    else:
        # LTE/UMTS/NR - TA is round-trip
        center_distance = (ta_value * resolution) / 2
        min_distance = max(0, center_distance - resolution / 4)
        max_distance = center_distance + resolution / 4

    return DistanceEstimate(
        min_distance_m=min_distance,
        max_distance_m=max_distance,
        center_distance_m=center_distance,
        technology=technology,
        timing_advance=ta_value,
        resolution_m=resolution
    )


def ta_to_ring_coordinates(
    lat: float,
    lon: float,
    distance_m: float,
    num_points: int = 64
) -> list[tuple[float, float]]:
    """
    Generate circle coordinates around a point for map display.

    Args:
        lat: Center latitude
        lon: Center longitude
        distance_m: Radius in meters
        num_points: Number of points to generate

    Returns:
        List of (lat, lon) tuples forming a circle
    """
    if distance_m <= 0:
        return [(lat, lon)]

    # Earth radius in meters
    R = 6371000

    # Convert to radians
    lat_rad = math.radians(lat)
    lon_rad = math.radians(lon)

    # Angular distance in radians
    d = distance_m / R

    points = []
    for i in range(num_points):
        bearing = (2 * math.pi * i) / num_points

        # Calculate new point
        new_lat = math.asin(
            math.sin(lat_rad) * math.cos(d) +
            math.cos(lat_rad) * math.sin(d) * math.cos(bearing)
        )

        new_lon = lon_rad + math.atan2(
            math.sin(bearing) * math.sin(d) * math.cos(lat_rad),
            math.cos(d) - math.sin(lat_rad) * math.sin(new_lat)
        )

        points.append((math.degrees(new_lat), math.degrees(new_lon)))

    # Close the ring
    if points:
        points.append(points[0])

    return points


def estimate_max_range(technology: CellularTechnology) -> float:
    """
    Get the maximum theoretical range for a technology based on TA limits.

    Returns:
        Maximum range in meters
    """
    max_ta = MAX_TA_VALUE.get(technology, 1282)
    resolution = TA_RESOLUTION.get(technology, 78.12)

    if technology == CellularTechnology.GSM:
        return max_ta * resolution
    else:
        return (max_ta * resolution) / 2


def format_distance(distance_m: float) -> str:
    """Format distance for display."""
    if distance_m < 1000:
        return f"{distance_m:.0f}m"
    else:
        return f"{distance_m/1000:.2f}km"
