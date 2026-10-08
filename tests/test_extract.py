from scam_detector.extract import extract_all, extract_amounts, extract_links, extract_phones


def hosts(text):
    return [l["host"] for l in extract_links(text)]


def numbers(text):
    return [p["number"] for p in extract_phones(text)]


# --- links ---------------------------------------------------------------

def test_full_url():
    links = extract_links("לעדכון: https://israelpost-track.top/il")
    assert links[0]["url"] == "https://israelpost-track.top/il"
    assert links[0]["domain"] == "israelpost-track.top"
    assert links[0]["tld"] == "top"


def test_bare_domain_with_path():
    assert hosts("ניתן להיכנס לקישור הבא: did.li/Route6") == ["did.li"]
    assert hosts("לבדיקת זכאותך : forms-il.com") == ["forms-il.com"]
    assert hosts("קליק מהיר >> D4U.co.il/li/MRZEJ") == ["d4u.co.il"]


def test_www_link():
    assert hosts("כנס/י ללינק www.aig.co.il/t/b7DqpkJV4U . בברכה") == ["www.aig.co.il"]


def test_two_part_suffix_domain():
    link = extract_links("https://customers.meitavdash.co.il/v2/login")[0]
    assert link["domain"] == "meitavdash.co.il"
    assert extract_links("http://go.gov.il/zimuntor")[0]["domain"] == "go.gov.il"


def test_trailing_punctuation_removed():
    assert extract_links("More info: https://mobitel.lk/samsung-a06-offer.")[0]["url"] == \
        "https://mobitel.lk/samsung-a06-offer"
    assert extract_links("[לינק](https://l5k.me/xGyQw)")[0]["url"] == "https://l5k.me/xGyQw"


def test_url_stops_at_hebrew():
    assert extract_links("https://bit.ly/abcהודעה")[0]["url"] == "https://bit.ly/abc"


def test_not_links():
    assert hosts('בעלות של 4.90 ש"ח') == []
    assert hosts("Rs. 16,600/- upfront") == []
    assert hosts("ט.ל.ח | המלאי מוגבל") == []
    assert hosts("כתובת המייל [EMAIL] או user@gmail.com") == []
    assert hosts("הקורס ייפתח בתאריך 02.05.2023") == []


# --- phones --------------------------------------------------------------

def test_mobile_and_landline():
    assert numbers("להסרה השב הסר למספר 052-9991904") == ["+972529991904"]
    assert numbers("בטלפון: 050-558-5555 או במייל") == ["+972505585555"]
    assert numbers("לצלצל ל03-7776770") == ["+97237776770"]
    assert numbers("טל: 036944044,") == ["+97236944044"]


def test_star_number():
    phones = extract_phones("לבירורים נוספים : *35592")
    assert phones == [{"number": "*35592", "type": "star", "source": "text"}]


def test_whatsapp_link_phone():
    phones = extract_phones("https://wa.me/972503900432")
    assert phones == [{"number": "+972503900432", "type": "mobile", "source": "whatsapp_link"}]
    assert numbers("https://api.whatsapp.com/send?phone=972538880349") == ["+972538880349"]


def test_not_phones():
    assert numbers("מספר הצעתך: 600061258023") == []        # quote number
    assert numbers("סטטוס משלוח: IL972501234567 נעצר") == []  # tracking code
    assert numbers("מס' מעקב 56302009") == []
    assert numbers("https://ilto.run/0501234567") == []      # digits inside a link


# --- amounts -------------------------------------------------------------

def test_shekel_amounts():
    found = [(a["amount"], a["currency"]) for a in extract_amounts(
        'דמי משלוח 4.90 ש"ח, שקית ב-1,000 ₪ ו-2.50 שקלים לחודש')]
    assert found == [(4.9, "ILS"), (1000.0, "ILS"), (2.5, "ILS")]


def test_other_currencies():
    found = [(a["amount"], a["currency"]) for a in extract_amounts(
        "Earn $300-$800/day. Just Rs. 16,600/- upfront")]
    assert found == [(300.0, "USD"), (800.0, "USD"), (16600.0, "LKR")]


def test_number_without_currency_is_not_money():
    assert extract_amounts("עט אידוי ב100") == []


def test_extract_all():
    result = extract_all("קיים חוב של 38.70 ש\"ח: did.li/Route6 לבירורים *35592")
    assert [l["host"] for l in result["links"]] == ["did.li"]
    assert [p["number"] for p in result["phones"]] == ["*35592"]
    assert [a["amount"] for a in result["amounts"]] == [38.7]
