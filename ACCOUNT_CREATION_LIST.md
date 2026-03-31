# Account Creation List

Credentials needed to unblock v1.6 Full Activation milestone (15 of 27 requirements blocked).

## 1. Reddit API (instant)

1. Go to **https://www.reddit.com/prefs/apps**
2. Log in (or create account)
3. Click **"Create app"** at the bottom
4. Select **"script"** type
5. Name: anything (e.g. "lobsec-sentiment")
6. Redirect URI: `http://localhost:8080`
7. Click **Create app**
8. Save these values:
   - **Client ID** — 14-char string under the app name
   - **Client Secret** — string next to "secret"
   - Your Reddit **username** and **password**

**Unblocks:** QUAL-02 (Reddit sentiment collection)

## 2. NewsAPI (5 minutes)

1. Go to **https://newsapi.org/register**
2. Fill in email, password, name, use case
3. Verify email
4. Copy the **API Key** from your dashboard

Free tier: 100 requests/day, dev-only, 24h article delay. Sufficient for monthly sentiment snapshots.

**Unblocks:** QUAL-03 (NewsAPI headline sentiment)

## 3. Dubai Pulse (up to 14 days)

1. Go to **https://www.dubaipulse.gov.ae**
2. Browse and **request access** to these datasets:
   - DLD transactions (`dld_transactions`)
   - Ejari rentals (`dld_rent_contracts`)
   - DEWA connections (`dewa_electricity_new_connection`)
   - Building permits (`dm_building_permits`)
   - RTA metro (`rta_metro_ridership`)
   - RTA vehicles (`rta_car_registration`)
   - DTCM tourism (`dtcm_visitors_count_by_nationality`)
3. Wait for **2 emails** (up to 14 days):
   - Email 1: **API Key** (= client_id)
   - Email 2: **API Secret** (= client_secret)

OAuth2 tokens expire every 30 minutes — our client handles refresh automatically.

**Unblocks:** PULSE-01 through PULSE-08, QUAL-04, QUAL-05, VERIF-01, VERIF-02 (13 requirements)

## Credentials to Provide

Once registered, paste these values (they will be stored in HSM):

```
# Reddit
REDDIT_CLIENT_ID=
REDDIT_CLIENT_SECRET=
REDDIT_USERNAME=
REDDIT_PASSWORD=

# NewsAPI
NEWSAPI_KEY=

# Dubai Pulse (when emails arrive)
DUBAI_PULSE_API_KEY=
DUBAI_PULSE_API_SECRET=
```
