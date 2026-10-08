"""Pull links, phone numbers and money amounts out of a message.

Plain Python, no network: links are only read as text, never opened.
"""
import re
from urllib.parse import parse_qs, urlsplit

# Top-level domains we accept for links written without http:// (e.g. "did.li/Route6").
# Without this list, things like "Rs. 16" or "4.90" would look like domains.
# Links that start with http:// or www. are accepted with any TLD.
BARE_TLDS = {
    "com", "net", "org", "info", "biz", "pro", "io", "co", "me", "app", "dev", "ai",
    "top", "shop", "xyz", "site", "online", "store", "club", "link", "live", "run",
    "click", "vip", "win", "buzz", "icu", "cc", "tv", "ws", "vu", "cx", "im", "ly",
    "il", "ru", "is", "li", "de", "be", "at", "fr", "uk", "us", "eu", "lk", "in", "cn",
}
# Two-part endings where the registered name is one label further left (paypal.co.il)
TWO_PART_SUFFIXES = {
    "co.il", "org.il", "gov.il", "ac.il", "net.il", "muni.il", "k12.il", "idf.il",
    "co.uk", "org.uk", "com.au", "co.in",
}

_HEBREW = "֐-׿"
_PATH = rf"(?:[/?#][^\s{_HEBREW}<>\"']*)?"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

_URL_RE = re.compile(
    rf"""
    (?<![@\w.-])                                   # not inside an email or a longer word
    (?:
        (?P<scheme>https?://)[^\s{_HEBREW}<>"']+   # http(s)://anything
      | (?P<www>www\.){_LABEL}(?:\.{_LABEL})+{_PATH} # www.example.com
      | (?P<bare>{_LABEL}(?:\.{_LABEL})*\.(?P<tld>[a-z]{{2,12}})){_PATH}  # did.li/Route6
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_TRAILING = ".,;:!?)('\"»*"

# Israeli phone numbers: +972 / 972 / 0 prefix, optional dashes or spaces; star numbers; 1-800/1-700
_PHONE_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_*+])
    (?:
        (?P<intl>\+?972[-\s]?)(?P<rest1>[2-9](?:[-\s]?\d){7,8})
      | (?P<local>0[2-9](?:[-\s]?\d){7,8})
      | (?P<tollfree>1[-\s]?[78]00(?:[-\s]?\d){6})
    )
    (?![A-Za-z0-9_])
    | (?<![A-Za-z0-9_*])(?P<star>\*\d{3,5})(?!\d)
    """,
    re.VERBOSE,
)

_NUM = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_SHEKEL = r"(?:₪|ש\"ח|ש״ח|ש''ח|שקלים|שקל|ש\"ח|NIS|ILS)"
_MONEY_RE = re.compile(
    rf"""
      (?P<a1>{_NUM})\s?(?:-\s?)?(?P<c1>{_SHEKEL})          # 300₪, 4.90 ש"ח, 2.50 שקלים
    | (?P<c2>₪|\$|€|£)\s?(?P<a2>{_NUM})                    # ₪300, $52.10
    | (?P<a3>{_NUM})\s?(?P<c3>\$|€|£)                      # 300$
    | (?P<c4>Rs\.?)\s?(?P<a4>{_NUM})                       # Rs. 16,600
    """,
    re.VERBOSE,
)
_CURRENCY = {"$": "USD", "€": "EUR", "£": "GBP", "Rs": "LKR", "Rs.": "LKR"}


def _registered_domain(host):
    labels = host.split(".")
    n = 3 if ".".join(labels[-2:]) in TWO_PART_SUFFIXES else 2
    return ".".join(labels[-n:])


def extract_links(text):
    links = []
    for m in _URL_RE.finditer(text):
        if m.group("bare") and m.group("tld").lower() not in BARE_TLDS:
            continue
        url = m.group(0).rstrip(_TRAILING)
        full = url if m.group("scheme") else "http://" + url
        host = (urlsplit(full).hostname or "").lower().rstrip(".")
        if not host or "." not in host:
            continue
        links.append({
            "url": url,
            "host": host,
            "domain": _registered_domain(host),
            "tld": host.rsplit(".", 1)[-1],
            "has_scheme": bool(m.group("scheme")),
        })
    return links


def _normalize_phone(m):
    if m.group("star"):
        return m.group("star"), "star"
    if m.group("tollfree"):
        return re.sub(r"\D", "", m.group("tollfree")), "toll_free"
    digits = re.sub(r"\D", "", m.group("rest1") or m.group("local"))
    digits = digits.lstrip("0")
    kind = "mobile" if digits.startswith("5") else "landline"
    return "+972" + digits, kind


def _whatsapp_phone(link):
    """WhatsApp links carry a phone number: wa.me/9725... or api.whatsapp.com/send?phone=..."""
    parts = urlsplit(link["url"] if link["has_scheme"] else "http://" + link["url"])
    if link["host"] == "wa.me":
        number = parts.path.strip("/")
    elif link["host"].endswith("whatsapp.com"):
        number = (parse_qs(parts.query).get("phone") or [""])[0]
    else:
        return None
    return number if number.isdigit() else None


def extract_phones(text, links=None):
    links = extract_links(text) if links is None else links
    # Remove links first so digits inside URLs (tracking codes) aren't read as phones
    plain = _URL_RE.sub(" ", text)
    phones, seen = [], set()

    def add(number, kind, source):
        if number not in seen:
            seen.add(number)
            phones.append({"number": number, "type": kind, "source": source})

    for m in _PHONE_RE.finditer(plain):
        add(*_normalize_phone(m), "text")
    for link in links:
        wa = _whatsapp_phone(link)
        if wa:
            m = _PHONE_RE.fullmatch(wa) or _PHONE_RE.fullmatch("0" + wa)
            if m:
                add(*_normalize_phone(m), "whatsapp_link")
    return phones


def extract_amounts(text):
    plain = _URL_RE.sub(" ", text)
    amounts = []
    for m in _MONEY_RE.finditer(plain):
        for i in "1234":
            if m.group(f"a{i}"):
                raw_amount, cur = m.group(f"a{i}"), m.group(f"c{i}")
                break
        amounts.append({
            "amount": float(raw_amount.replace(",", "")),
            "currency": _CURRENCY.get(cur, "ILS"),
            "text": m.group(0).strip(),
        })
    return amounts


def extract_all(text):
    links = extract_links(text)
    return {
        "links": links,
        "phones": extract_phones(text, links),
        "amounts": extract_amounts(text),
    }
