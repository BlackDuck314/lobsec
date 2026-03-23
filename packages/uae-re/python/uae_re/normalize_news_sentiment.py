"""
News Sentiment Normalization Module (SENT-02)

Reads raw news sentiment JSON from collect_news_sentiment.py and produces
normalized daily metric records for the analytics database.

Metrics produced (4 total):
  - uae|news_sentiment_mean_compound:   Mean VADER compound score
  - uae|news_sentiment_bullish_ratio:   Proportion with compound > 0.05
  - uae|news_sentiment_bearish_ratio:   Proportion with compound < -0.05
  - uae|news_sentiment_article_count:   Total articles scored

Empty collection handling: output records with value=0 for counts and 0.0 for
ratios/mean_compound (neutral sentinel is valid; 0.0 compound = neutral).

Bridge pattern:
  Read:  {"filePath": str, "collectedAt": str, "source": str} from stdin
  Write: [{source, measurement_date, metric_name, value, available_date}] to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import sys
from datetime import datetime
from typing import Any

from .schemas.news_sentiment_schema import validate_news_sentiment_json


def _compute_news_metrics(
    articles: list[dict],
    measurement_date: str,
    collected_at: str,
    source: str = "news-sentiment",
) -> list[dict[str, Any]]:
    """Compute sentiment metrics for news articles.

    Args:
        articles: List of article dicts with 'compound' field.
        measurement_date: ISO date string for the measurement period.
        collected_at: ISO timestamp for available_date.
        source: Source identifier.

    Returns:
        List of metric records.
    """
    metrics = []
    article_count = len(articles)

    if article_count == 0:
        # Empty collection -- produce zero-value records
        for suffix in ["_mean_compound", "_bullish_ratio", "_bearish_ratio", "_article_count"]:
            metrics.append({
                "source": source,
                "measurement_date": measurement_date,
                "metric_name": f"uae|news_sentiment{suffix}",
                "value": 0.0,
                "available_date": collected_at,
            })
        return metrics

    compounds = [a["compound"] for a in articles]
    mean_compound = sum(compounds) / len(compounds)
    bullish_count = sum(1 for c in compounds if c > 0.05)
    bearish_count = sum(1 for c in compounds if c < -0.05)

    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": "uae|news_sentiment_mean_compound",
        "value": float(mean_compound),
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": "uae|news_sentiment_bullish_ratio",
        "value": float(bullish_count / article_count),
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": "uae|news_sentiment_bearish_ratio",
        "value": float(bearish_count / article_count),
        "available_date": collected_at,
    })
    metrics.append({
        "source": source,
        "measurement_date": measurement_date,
        "metric_name": "uae|news_sentiment_article_count",
        "value": float(article_count),
        "available_date": collected_at,
    })

    return metrics


def normalize_news_sentiment(file_path: str, collected_at: str) -> list[dict[str, Any]]:
    """Normalize news sentiment data to daily metrics.

    Args:
        file_path: Path to raw news sentiment JSON file.
        collected_at: ISO timestamp when data was collected (available_date).

    Returns:
        List of metric records.
    """
    validate_news_sentiment_json(file_path)

    with open(file_path) as f:
        raw = json.load(f)

    articles = raw.get("articles", [])

    # Use collection date as measurement date (daily collection)
    collected_dt = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    measurement_date = collected_dt.strftime("%Y-%m-%d")

    # Use available_date from raw data if present
    available_date = raw.get("collectedAt", collected_at)
    if "T" in available_date:
        available_date = available_date[:10]

    metrics = _compute_news_metrics(
        articles, measurement_date, available_date, "news-sentiment"
    )

    print(
        f"Normalized {len(metrics)} news sentiment records from {len(articles)} articles",
        file=sys.stderr,
    )
    return metrics


def main() -> None:
    """Entry point: read stdin, normalize, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        file_path = input_data["filePath"]
        collected_at = input_data["collectedAt"]

        result = normalize_news_sentiment(file_path, collected_at)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
