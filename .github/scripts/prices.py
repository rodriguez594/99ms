"""Fetch stock, crypto and currency prices for 99MS into prices.json.

Stocks come from Yahoo Finance and crypto from CoinGecko. The app reads the file from the
prices branch; crypto spot prices are also fetched live in the browser.
"""
import json, sys, time, urllib.request

UA = {"User-Agent": "Mozilla/5.0 (99ms.dk price fetcher)"}

STOCKS = {
    # Denmark
    "NOVO-B.CO": "Novo Nordisk B", "MAERSK-B.CO": "A.P. Møller - Mærsk B", "DSV.CO": "DSV", "VWS.CO": "Vestas Wind Systems",
    "ORSTED.CO": "Ørsted", "CARL-B.CO": "Carlsberg B", "DANSKE.CO": "Danske Bank", "COLO-B.CO": "Coloplast B",
    "GMAB.CO": "Genmab", "PNDORA.CO": "Pandora", "NSIS-B.CO": "Novonesis B", "DEMANT.CO": "Demant", "GN.CO": "GN Store Nord",
    "TRYG.CO": "Tryg", "JYSK.CO": "Jyske Bank", "NKT.CO": "NKT", "ROCK-B.CO": "Rockwool B", "ZEAL.CO": "Zealand Pharma",
    "BAVA.CO": "Bavarian Nordic", "AMBU-B.CO": "Ambu B", "ISS.CO": "ISS", "FLS.CO": "FLSmidth", "NDA-DK.CO": "Nordea",
    # USA
    "AAPL": "Apple", "MSFT": "Microsoft", "NVDA": "Nvidia", "AMZN": "Amazon", "GOOGL": "Alphabet (Google)", "META": "Meta",
    "TSLA": "Tesla", "NFLX": "Netflix", "AMD": "AMD", "AVGO": "Broadcom", "JPM": "JPMorgan Chase", "V": "Visa",
    "KO": "Coca-Cola", "DIS": "Disney", "NKE": "Nike", "PLTR": "Palantir", "COIN": "Coinbase", "UBER": "Uber",
    "SPOT": "Spotify", "BRK-B": "Berkshire Hathaway B", "LLY": "Eli Lilly", "ORCL": "Oracle", "INTC": "Intel",
    "PYPL": "PayPal", "SHOP": "Shopify", "MSTR": "Strategy (MicroStrategy)", "HOOD": "Robinhood", "WMT": "Walmart",
    "MCD": "McDonald's", "SBUX": "Starbucks", "BA": "Boeing", "GME": "GameStop",
    # Europe
    "ASML.AS": "ASML", "SAP.DE": "SAP", "MC.PA": "LVMH", "NESN.SW": "Nestlé", "VOLV-B.ST": "Volvo B", "EQNR.OL": "Equinor",
    # Funds
    "SPY": "S&P 500 (SPDR SPY)", "QQQ": "Nasdaq 100 (Invesco QQQ)", "VOO": "S&P 500 (Vanguard VOO)",
    "IWDA.AS": "iShares Core MSCI World", "VWRL.AS": "Vanguard FTSE All-World", "SXR8.DE": "iShares Core S&P 500", "EUNL.DE": "iShares Core MSCI World (EUNL)",
}
CRYPTO = {
    "bitcoin": ("BTC", "Bitcoin"), "ethereum": ("ETH", "Ethereum"), "solana": ("SOL", "Solana"), "ripple": ("XRP", "XRP"),
    "binancecoin": ("BNB", "BNB"), "cardano": ("ADA", "Cardano"), "dogecoin": ("DOGE", "Dogecoin"), "tron": ("TRX", "TRON"),
    "avalanche-2": ("AVAX", "Avalanche"), "chainlink": ("LINK", "Chainlink"), "polkadot": ("DOT", "Polkadot"),
    "litecoin": ("LTC", "Litecoin"), "shiba-inu": ("SHIB", "Shiba Inu"), "pepe": ("PEPE", "Pepe"), "sui": ("SUI", "Sui"),
    "the-open-network": ("TON", "Toncoin"), "tether": ("USDT", "Tether"), "usd-coin": ("USDC", "USD Coin"),
}
OLD_URL = "https://raw.githubusercontent.com/{repo}/prices/prices.json"


def get(url, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001 - retry anything, report the last
            err = e
            time.sleep(2 + 3 * i)
    raise err


def r(v):
    """Keep about 6 significant digits so the file stays small."""
    if v is None:
        return None
    return float(f"{v:.6g}")


def chart(sym, rng, interval):
    res = get(f"https://query2.finance.yahoo.com/v8/finance/chart/{sym}?range={rng}&interval={interval}")["chart"]["result"][0]
    ts, closes = res.get("timestamp") or [], res["indicators"]["quote"][0].get("close") or []
    pts = [[t, r(c)] for t, c in zip(ts, closes) if c is not None]
    return res["meta"], pts


def main(repo):
    out = {"t": int(time.time() * 1000), "fx": {"DKK": 1}, "stocks": {}, "crypto": {}}
    for code, sym in (("USD", "DKK=X"), ("EUR", "EURDKK=X"), ("SEK", "SEKDKK=X"), ("NOK", "NOKDKK=X"), ("CHF", "CHFDKK=X"), ("GBP", "GBPDKK=X")):
        meta, _ = chart(sym, "1d", "1d")
        out["fx"][code] = r(meta["regularMarketPrice"])

    for sym, name in STOCKS.items():
        try:
            meta, year = chart(sym, "1y", "1d")
            _, week = chart(sym, "5d", "30m")
            p = meta["regularMarketPrice"]
            # The daily closes end with today once the market has traded; the close before that is the reference.
            day = lambda t: time.strftime("%Y-%m-%d", time.gmtime(t))
            traded_today = year and day(year[-1][0]) == day(meta.get("regularMarketTime", 0))
            pc = (year[-2][1] if len(year) > 1 else p) if traded_today else (year[-1][1] if year else p)
            out["stocks"][sym] = {"n": name, "c": meta.get("currency", "USD"), "p": r(p), "pc": r(pc),
                                  "mt": meta.get("regularMarketTime"), "d": [[t // 60, c] for t, c in year],
                                  "w": [[t // 60, c] for t, c in week]}
        except Exception as e:  # noqa: BLE001
            print("skip", sym, e, file=sys.stderr)
        time.sleep(0.3)

    ids = ",".join(CRYPTO)
    spot = get(f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd&include_24hr_change=true")
    old = {}
    try:
        old = get(OLD_URL.format(repo=repo), tries=1).get("crypto", {})
    except Exception:  # noqa: BLE001 - first run
        pass
    fresh_hist = time.gmtime().tm_min < 12 or not old
    for cid, (s, name) in CRYPTO.items():
        if cid not in spot:
            continue
        c = {"s": s, "n": name, "p": r(spot[cid]["usd"]), "ch": r(spot[cid].get("usd_24h_change"))}
        prev = old.get(cid, {})
        if fresh_hist or "d" not in prev:
            try:
                c["d"] = [[int(t // 60000), r(v)] for t, v in get(f"https://api.coingecko.com/api/v3/coins/{cid}/market_chart?vs_currency=usd&days=365&interval=daily")["prices"]]
                time.sleep(2.5)
                c["w"] = [[int(t // 60000), r(v)] for t, v in get(f"https://api.coingecko.com/api/v3/coins/{cid}/market_chart?vs_currency=usd&days=7")["prices"]][::2]
                time.sleep(2.5)
            except Exception as e:  # noqa: BLE001
                print("history skip", cid, e, file=sys.stderr)
        for k in ("d", "w"):
            if k not in c and k in prev:
                c[k] = prev[k]
        out["crypto"][cid] = c

    with open("prices.json", "w") as f:
        json.dump(out, f, separators=(",", ":"), ensure_ascii=False)
    print(len(out["stocks"]), "stocks,", len(out["crypto"]), "crypto, fx", out["fx"])


if __name__ == "__main__":
    main(sys.argv[1])
