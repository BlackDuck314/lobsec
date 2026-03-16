"""
Reddit Sentiment Normalization Module

Reads raw Reddit sentiment JSON from collect_sentiment.py and produces
normalized metric records for the analytics database.

Metrics produced:
  Overall (all subreddits):
    - dubai|sentiment_mean_compound:   Mean VADER compound score
    - dubai|sentiment_bullish_ratio:   Proportion with compound > 0.05
    - dubai|sentiment_bearish_ratio:   Proportion with compound < -0.05
    - dubai|sentiment_post_count:      Total posts found

  Per-subreddit variants:
    - dubai|sentiment_{subreddit}_mean_compound
    - dubai|sentiment_{subreddit}_bullish_ratio
    - dubai|sentiment_{subreddit}_bearish_ratio
    - dubai|sentiment_{subreddit}_post_count

Empty week handling: output records with value=0 for counts and 0.0 for
ratios/mean_compound (neutral sentinel is valid; 0.0 compound = neutral).

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str} from stdin
  Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
  Errors: print to stderr, sys.exit(1)

NORM-02: available_date = collectedAt
NORM-04: Hard error on schema validation failure
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from .schemas.sentiment_schema import sentiment_schema


def _compute_sentiment_metrics(
    posts_df: pd.DataFrame,
    prefix: str,
    measurement_date: str,
    collected_at: str,
    source: str = "reddit-sentiment",
) -> list[dict]:
    """Compute sentiment metrics for a set of posts.

    Args:
        posts_df: DataFrame of post records with 'compound' column.
        prefix: Metric name prefix (e.g., 'dubai|sentiment' or 'dubai|sentiment_dubai').
        measurement_date: ISO date string for the measurement period.
        collected_at: ISO timestamp for available_date.
        source: Source identifier.

    Returns:
        List of metric records.
    """
    metrics = []
    post_count = len(posts_df)

    if post_count == 0:
        # Empty week — produce zero-value records
        metrics.append({
            "source": source,
            "measurement_date": measurement_date,
            "metric_name": f"{prefix}_mean_compound",
            "value": 0.0,
            "available_date": collected_at,
        })
        metrics.append({
            "source": source,
            "measurement_date": measurement_date,
            "metric_name": f"{prefix}_bullish_ratio",
            "value": 0.0,
            "available_date": collected_at,
        })
        metrics.append({
            "source": source,
            "measurement_date": measurement_date,
            "metric_name": f"{prefix}_bearish_ratio",
            "value": 0.0,
            "available_date": collected_at,
        })
        metrics.append({
            "source": source,
            "measurement_date": measurement_date,
            "metric_name": f"{prefix}_post_count",
            "value": 0.0,
            "available_date": collected_at,
        })
        return metrics

    compound = posts_df["compound"]
    mean_compound = float(compound.mean())
    bullish_ratio = float((compound > 0.05).sum() / post_count)
    bearish_ratio = float((compound < -0.05).sum() / post_count)

    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": f"{prefix}_mean_compound",
        "value": mean_compound,
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": f"{prefix}_bullish_ratio",
        "value": bullish_ratio,
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": f"{prefix}_bearish_ratio",
        "value": bearish_ratio,
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": f"{prefix}_post_count",
        "value": float(post_count),
        "available_date": collected_at,
    })

    return metrics


def normalize_sentiment(file_path: str, collected_at: str) -> list[dict]:
    """Normalize Reddit sentiment data to daily metrics.

    Args:
        file_path: Path to raw Reddit sentiment JSON file from collect_sentiment.py.
        collected_at: ISO timestamp when data was collected (available_date).

    Returns:
        List of metric records: [{source, measurement_date, metric_name, value, available_date}]
    """
    source = "reddit-sentiment"

    # Load raw data
    with open(file_path) as f:
        raw = json.load(f)

    posts = raw.get("posts", [])

    # Use collection date as measurement date (daily collection)
    # Use start of the collection day for consistent daily measurement
    collected_dt = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    measurement_date = collected_dt.strftime("%Y-%m-%d")

    # Build DataFrame
    if posts:
        df = pd.DataFrame(posts)
        # Validate schema
        try:
            df = sentiment_schema.validate(df)
        except Exception as e:
            print(f"Schema validation failed: {e}", file=sys.stderr)
            raise
    else:
        # Empty — create an empty DataFrame with required columns
        df = pd.DataFrame(columns=["subreddit", "post_id", "compound", "created_utc", "score"])

    metrics = []

    # Overall metrics across all subreddits
    metrics.extend(_compute_sentiment_metrics(
        df, "dubai|sentiment", measurement_date, collected_at, source
    ))

    # Per-subreddit metrics
    subreddits = df["subreddit"].unique() if not df.empty else []
    for subreddit in subreddits:
        sub_df = df[df["subreddit"] == subreddit]
        prefix = f"dubai|sentiment_{subreddit}"
        metrics.extend(_compute_sentiment_metrics(
            sub_df, prefix, measurement_date, collected_at, source
        ))

    return metrics


def main() -> None:
    """Entry point: read stdin, normalize, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        result = normalize_sentiment(file_path, collected_at)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
