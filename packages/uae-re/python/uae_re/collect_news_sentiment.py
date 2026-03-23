"""
NewsAPI Headline Sentiment Collector (SENT-02)

Fetches UAE real estate news headlines from NewsAPI.org and scores each
article with VADER sentiment analysis.

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer


# NewsAPI endpoint
NEWSAPI_BASE = "https://newsapi.org/v2/everything"

# Search query for UAE real estate headlines
QUERY = (
    '"UAE real estate" OR "Dubai property" OR "Dubai rent" '
    'OR "Abu Dhabi housing" OR "Dubai apartment" OR "UAE mortgage" '
    'OR "DIFC" OR "Emaar"'
)


def collect_news_sentiment(output_dir: str) -> dict:
    """Fetch news headlines and compute VADER sentiment scores.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int}

    Raises:
        ValueError: If NEWSAPI_KEY is not set.
    """
    api_key = os.getenv("NEWSAPI_KEY", "")
    if not api_key:
        raise ValueError(
            "Missing NEWSAPI_KEY environment variable. "
            "Register a free developer account at https://newsapi.org/register "
            "and store the API key in HSM."
        )

    # Prepare output directory
    sentiment_dir = Path(output_dir) / "news-sentiment"
    sentiment_dir.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc).isoformat()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = sentiment_dir / f"{today}.json"

    # Date range: last 30 days
    date_from = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    date_to = today

    print(f"Fetching news from {date_from} to {date_to}...", file=sys.stderr)

    # Fetch from NewsAPI (API key via header for security)
    resp = requests.get(
        NEWSAPI_BASE,
        params={
            "q": QUERY,
            "language": "en",
            "sortBy": "publishedAt",
            "pageSize": 100,
            "from": date_from,
            "to": date_to,
        },
        headers={
            "X-Api-Key": api_key,
        },
        timeout=30,
    )
    resp.raise_for_status()

    response_data = resp.json()
    if response_data.get("status") != "ok":
        error_code = response_data.get("code", "unknown")
        error_msg = response_data.get("message", "Unknown error")
        raise ValueError(f"NewsAPI error: {error_code} - {error_msg}")

    articles = response_data.get("articles", [])
    print(f"  Found {len(articles)} articles", file=sys.stderr)

    # VADER-score each article
    analyzer = SentimentIntensityAnalyzer()
    scored_articles = []

    for article in articles:
        title = article.get("title", "") or ""
        description = article.get("description", "") or ""
        text = f"{title} {description}".strip()

        if not text:
            continue

        scores = analyzer.polarity_scores(text)

        scored_articles.append({
            "title": title,
            "source_name": article.get("source", {}).get("name", ""),
            "publishedAt": article.get("publishedAt", ""),
            "url": article.get("url", ""),
            "compound": scores["compound"],
            "pos": scores["pos"],
            "neg": scores["neg"],
            "neu": scores["neu"],
        })

    total_articles = len(scored_articles)
    print(f"  Scored {total_articles} articles with VADER", file=sys.stderr)

    # Write raw output
    output = {
        "collectedAt": collected_at,
        "articles": scored_articles,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {total_articles} articles to {out_path}", file=sys.stderr)
    return {"filePath": str(out_path), "rowCount": total_articles}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_news_sentiment(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
