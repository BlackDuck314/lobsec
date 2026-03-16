"""
Reddit Sentiment Collection Module (COLL-24)

Fetches posts from r/dubai and r/dubairealestate via PRAW (read-only)
and scores each post with VADER sentiment analysis. Writes raw scores
to /opt/lobsec/data/raw/reddit-sentiment/{date}.json.

Reddit credentials (REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET) must be
available as environment variables. They are stored in the HSM and
injected at runtime via the lobsec service environment.

Bridge pattern:
  Read:  {"outputDir": "/opt/lobsec/data/raw"} from stdin
  Write: {"filePath": str, "rowCount": int} to stdout
  Errors: print to stderr, sys.exit(1)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import praw
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer


# Subreddits to monitor for Dubai real estate sentiment
SUBREDDITS = ["dubai", "dubairealestate"]

# Search query covers property, rental, visa, and mobility signals
SEARCH_QUERY = 'rent OR apartment OR property OR landlord OR visa OR "move out" OR "leaving Dubai"'


def collect_sentiment(output_dir: str) -> dict:
    """Fetch Reddit posts and compute VADER sentiment scores.

    Args:
        output_dir: Base directory for output files.

    Returns:
        {"filePath": str, "rowCount": int} where rowCount is total posts fetched.

    Raises:
        ValueError: If REDDIT_CLIENT_ID or REDDIT_CLIENT_SECRET are not set.
    """
    client_id = os.getenv("REDDIT_CLIENT_ID", "")
    client_secret = os.getenv("REDDIT_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        raise ValueError(
            "Missing Reddit API credentials: REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET "
            "must be set as environment variables. "
            "Create a Reddit application at https://www.reddit.com/prefs/apps "
            "(type: script) and store credentials in HSM."
        )

    # Prepare output directory
    sentiment_dir = Path(output_dir) / "reddit-sentiment"
    sentiment_dir.mkdir(parents=True, exist_ok=True)

    collected_at = datetime.now(timezone.utc).isoformat()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = sentiment_dir / f"{today}.json"

    # Initialize PRAW (read-only — no user credentials needed)
    reddit = praw.Reddit(
        client_id=client_id,
        client_secret=client_secret,
        user_agent="uae-re-intel/1.0 (by lobsec)",
    )

    # Initialize VADER sentiment analyzer
    analyzer = SentimentIntensityAnalyzer()

    all_posts = []

    for sub_idx, subreddit_name in enumerate(SUBREDDITS):
        print(f"Fetching from r/{subreddit_name}...", file=sys.stderr)

        try:
            subreddit = reddit.subreddit(subreddit_name)
            posts = list(subreddit.search(
                SEARCH_QUERY,
                limit=100,
                time_filter="week",
                sort="relevance",
            ))

            print(f"  Found {len(posts)} posts in r/{subreddit_name}", file=sys.stderr)

            for post in posts:
                # Compose text for sentiment analysis: title + selftext
                text = post.title
                if post.selftext:
                    text = f"{post.title} {post.selftext}"

                # VADER compound score: -1 (most negative) to +1 (most positive)
                scores = analyzer.polarity_scores(text)
                compound = scores["compound"]

                all_posts.append({
                    "subreddit": subreddit_name,
                    "post_id": post.id,
                    "created_utc": int(post.created_utc),
                    "compound": compound,
                    "score": post.score,  # Reddit upvotes
                    "title": post.title,
                })

        except Exception as e:
            print(f"Warning: Failed to fetch from r/{subreddit_name}: {e}", file=sys.stderr)

        # Rate limiting: pause between subreddits
        if sub_idx < len(SUBREDDITS) - 1:
            time.sleep(2)

    total_posts = len(all_posts)
    print(f"Total posts collected: {total_posts}", file=sys.stderr)

    # Write raw output
    output = {
        "collectedAt": collected_at,
        "posts": all_posts,
    }

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {total_posts} posts to {out_path}", file=sys.stderr)
    return {"filePath": str(out_path), "rowCount": total_posts}


def main() -> None:
    """Entry point: read stdin, collect, write stdout."""
    try:
        input_data = json.load(sys.stdin)
        output_dir = input_data.get("outputDir", "/opt/lobsec/data/raw")

        result = collect_sentiment(output_dir)

        json.dump(result, sys.stdout)
        sys.stdout.flush()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
