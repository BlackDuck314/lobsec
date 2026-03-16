"""
Reddit Sentiment Schema (pandera)

Validates the structure of raw Reddit sentiment posts as collected by
collect_sentiment.py. Each post record must have:
  - compound: float, VADER compound score in [-1, 1]
  - subreddit: string, subreddit name
  - post_id: string, Reddit post ID (unique)

NORM-04: Hard error on schema validation failure.
"""

import pandera as pa
from pandera import Column, DataFrameSchema

# Reddit sentiment posts schema
sentiment_schema = DataFrameSchema(
    {
        "subreddit": Column(
            str,
            nullable=False,
            description="Subreddit name (e.g., 'dubai', 'dubairealestate')",
        ),
        "post_id": Column(
            str,
            nullable=False,
            description="Reddit post ID (alphanumeric string)",
        ),
        "compound": Column(
            float,
            pa.Check.in_range(-1.0, 1.0),
            nullable=False,
            description="VADER compound sentiment score, -1 (negative) to +1 (positive)",
        ),
        "created_utc": Column(
            int,
            pa.Check.ge(0),
            nullable=False,
            description="Unix timestamp of post creation",
        ),
        "score": Column(
            int,
            nullable=True,
            description="Reddit post score (upvotes minus downvotes)",
        ),
    },
    coerce=True,
    strict=False,  # Allow additional columns (e.g., 'title' stored for debugging)
)
