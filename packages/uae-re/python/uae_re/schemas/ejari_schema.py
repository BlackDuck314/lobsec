"""
Ejari Rentals Schema (pandera)

Re-exports DLD schema since Ejari uses the same source CSV.
The filtering by trans_group_en=Rent happens during normalization.
"""

from .dld_schema import dld_schema as ejari_schema

__all__ = ["ejari_schema"]
