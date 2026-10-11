"""Warning-sign rules: plain, explainable checks that work alongside the trained model.

Each rule has a strength:
  very_strong  almost never in a real message (asking you to send a verification code)
  strong       common in scams, sometimes in real messages (pay through a link)
  medium       adds suspicion but is common in marketing too (urgency, short links)
and a short explanation and advice in Hebrew and English for the app to show.

Based on the National Cyber Directorate warnings (docs/cyber_directorate_summary.md)
and general scam patterns. Hebrew patterns match inside words on purpose, so prefixes
(ו, ה, ב, ל, ש, מ, כ) don't stop a match.
"""
import re

from scam_detector.extract import extract_all

VERY_STRONG, STRONG, MEDIUM = "very_strong", "strong", "medium"


def _any(pattern):
    return re.compile(pattern, re.IGNORECASE)


# --- word lists ------------------------------------------------------------

_CODE = _any(r"קוד(?!ם)|סיסמ|\bcode\b|\botp\b|password|\bpin\b")
_SEND = _any(r"שלח|תשלח|לשלוח|תעביר|להעביר|שתפ|תמסור|למסור|הקרא|\bsend\b|\bshare\b|\bforward\b|tell me|reply with")
_DONT_SHARE = _any(r"אין למסור|אל תמסור|לא למסור|אין לשתף|אל תשתפ|do not share|don'?t share|never share|not share")

_INSTALL = _any(r"להתקין|התקינו|התקן|להוריד|הורידו|להורדת|\binstall|\bdownload")
_APP = _any(r"אפליקצי|יישומון|\bapp\b|application|עדכון|\bupdate\b|גרסה|version")
# Scams *require* an install or update ("you must install the update to keep getting
# alerts"); marketing *invites* you ("download our app").
_INSTALL_REQUIRED = _any(r"(יש|נא|חובה|עליך|יש לך) (להתקין|להוריד|לעדכן)|עדכון (חובה|חירום|אבטחה|דחוף)|"
                         r"גרסה חדשה|כדי להמשיך|על מנת להמשיך|ללא העדכון|"
                         r"must (install|update|download)|required (update|install)|update required|"
                         r"security update|new version|to continue (receiving|using)")
_APP_STORES = {"play.google.com", "apps.apple.com"}

# (?<![א-ת]) = not inside a longer Hebrew word: "אקדמי " must not match "דמי ", "רחוב" not "חוב"
# A demand to pay: a debt, fine or fee, or a direct order to pay. Marketing that merely
# mentions payment ("payment methods", "pay in installments") doesn't count.
_DEBT = _any(r"(?<![א-ת])[והבלמש]?חוב(?![הר])|(?<![א-ת])[והבלמש]?דמי |עמלת|קנס|"
             r"\bdebt\b|\bfee\b|\bfine\b|overdue|outstanding (balance|amount)|penalty")
_PAY_ORDER = _any(r"(יש|נא|חובה|עליך|יש לך) (לשלם|להסדיר|לבצע (את )?התשלום|להשלים (את )?התשלום)|"
                  r"להסדרת (ה)?(חוב|תשלום)|לתשלום (ה)?(חוב|קנס|יתרה)|שלמו (עכשיו|כעת|היום|מיד)|"
                  r"please pay|pay (now|today|immediately|the (amount|fine|fee))|settle (your|the)|"
                  r"complete (your|the) payment")
_FREE = _any(r"ללא תשלום|ללא עלות|ללא התחייבות|בחינם|free of charge|no charge|\bfree\b")

_VERIFY = _any(r"לאמת|אימות|אמתו|עדכן את|לעדכן|עדכנו|להזין|הזינו|\bverify|confirm your|update your|validate")
_VERIFY_WHAT = _any(r"זהות|פרטי|כתובת|חשבון|כרטיס|identity|details|account|address|\bcard\b")
_BLOCKED = _any(r"נחסם|חסום|ייחסם|יושעה|הושעה|הוקפא|הוצאה לפועל|יוחזר|תוחזר|יועבר לבית המשפט|"
                r"רישיון .{0,25}(מוגבל|יוגבל|ייפסל|יישלל)|השלכות משפטיות|"
                r"\bblocked|suspended|\blocked\b|deactivat|will be closed|permanent closure|legal action")

_URGENT = _any(r"דחוף|באופן מיידי|מיידי|בהקדם|עוד היום|תוך \d+ ?(שעות|ש')|24 ש|הזדמנות אחרונה|מסתיימת היום|"
               r"מועד אחרון|אין להסתכן|"
               r"\burgent|immediately|right away|within \d+ ?hours|final notice|last chance|expires today")

# iPhone disables links from unknown senders until you reply; scams ask you to reply
# (or copy the link by hand) to get around that. Opt-out lines ("להסרה השב 1") don't match.
_ENABLE_LINK = _any(r"(להשיב|השיבו|השב|reply|respond)\W{0,3}(עם\W{0,3})?[\"'״]?(1|y|yes|כן)[\"'״]?.{0,60}(קישור|התראה|הקישור|link)|"
                    r"(להעתיק|העתיקו|העתק|copy)\W{1,3}(את\W)?(הקישור|ה?לינק|the link|link).{0,40}(דפדפן|browser)")

_MONEY_REQUEST = _any(r"להעביר (לי )?(כסף|תשלום)|צריך להעביר|תעביר(י)? לי|העברה דחופה|"
                      r"(לקנות|תקנה|תקני|קנה|קני) .{0,15}(כרטיס מתנה|גיפט ?קארד)|"
                      r"transfer (the )?money|send (me )?money|(buy|purchase) .{0,15}gift ?cards?|wire (the )?money")
_NEW_NUMBER = _any(r"המספר החדש שלי|זה המספר החדש|מספר חדש שלי|החלפתי מספר|הטלפון (שלי )?(נפל|נשבר|נגנב|הלך)|"
                   r"lost my phone|new number|my phone (broke|is broken)")

_PRIZE = _any(r"זכית|זכיתם|נבחרת לקבל|נבחרתם|you have won|you've won|\byou won|you('re| are) (a |the )?winner|"
              r"\bwinner!|awarded|selected to receive|guaranteed .{0,25}prize")

_DELIVERY = _any(r"משלוח|חבילה|חבילת|דבר דואר|\bpackage|\bparcel|delivery|shipment")
_DELIVERY_PROBLEM = _any(r"נעצר|ממתין|ממתינה|נכשל|לא ניתן היה|שגוי|חסר|יוחזר|תוחזר|"
                         r"on hold|failed|could not be delivered|unable to deliver|incomplete address|held")
_OFFICIAL_DELIVERY = {"israelpost.co.il", "dhl.com", "dhl.co.il", "ups.com", "fedex.com", "usps.com"}

_TOO_GOOD = _any(r"\d+% .{0,30}(רווח|תשואה|הרוויח)|הרוויחו מעל|תשואה מובטחת|רווח מובטח|"
                 r"earn \$?\d[\d,]*.{0,12}(/day|per day|a day|daily|/week|per week)|guaranteed (returns|profit|income)")

_OUR_RECORDS = _any(r"לפי נתונים|מרישומי|בהתאם לרישומי|נמצאת זכאי|הינך זכאי|לפי הרישומים|"
                    r"according to our records|our records show")

# Well-known link shorteners: they hide where the link really goes
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "shorturl.at", "qrco.de", "cutt.ly", "is.gd",
               "ow.ly", "rebrand.ly", "tiny.cc", "goo.gl", "rb.gy", "s.id"}

# Domain endings that are cheap and heavily used by scam sites
_RISKY_TLDS = {"ru", "top", "xyz", "shop", "vu", "icu", "buzz", "click", "cn", "tk", "ml",
               "ga", "cf", "gq", "cyou", "sbs", "rest", "monster"}

# A brand or "gov" inside a domain that isn't that brand's real domain
_OFFICIAL_DOMAINS = {
    "gov": None,  # any domain ending in .gov.il or .gov
    "israelpost": {"israelpost.co.il"},
    "paypal": {"paypal.com"},
    "shein": {"shein.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "apple": {"apple.com"},
    "microsoft": {"microsoft.com", "live.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com"},
    "leumi": {"leumi.co.il"},
    "hapoalim": {"bankhapoalim.co.il"},
    "isracard": {"isracard.co.il"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com", "dhl.co.il"},
}


def _is_official_gov(domain):
    return domain.endswith(".gov.il") or domain.endswith(".gov")


def _lookalike(link):
    host = link["host"]
    for brand, official in _OFFICIAL_DOMAINS.items():
        if brand not in host:
            continue
        if brand == "gov":
            if not _is_official_gov(host):
                return brand
        elif link["domain"] not in official:
            return brand
    return None


# --- rules -----------------------------------------------------------------

def _rule(id, strength, he, en, advice_he, advice_en):
    return {"id": id, "strength": strength, "he": he, "en": en,
            "advice_he": advice_he, "advice_en": advice_en}


def check(text, found=None):
    """Return (warning_signs, reassuring_signs) for a message."""
    found = extract_all(text) if found is None else found
    links = found["links"]
    signs = []
    add = signs.append

    if _CODE.search(text) and _SEND.search(text) and not _DONT_SHARE.search(text):
        add(_rule("asks_for_code", VERY_STRONG,
                  "מבקשים ממך לשלוח קוד אימות או סיסמה",
                  "Asks you to send a verification code or password",
                  "אף פעם אל תמסרו קוד אימות, לאף אחד. כך משתלטים על חשבון וואטסאפ או בנק.",
                  "Never share a verification code with anyone. This is how accounts get taken over."))

    store_only = links and all(l["host"] in _APP_STORES for l in links)
    if _INSTALL.search(text) and _APP.search(text) and links and not store_only:
        if _INSTALL_REQUIRED.search(text):
            add(_rule("install_from_link", STRONG,
                      "דורשים להתקין או לעדכן אפליקציה מקישור, לא מחנות האפליקציות",
                      "Requires you to install or update an app from a link, not from an app store",
                      "התקינו ועדכנו אפליקציות רק מ-Google Play או App Store, אף פעם מקישור בהודעה.",
                      "Only install or update apps from Google Play or the App Store, never from a message link."))
        else:
            add(_rule("app_download_link", MEDIUM,
                      "מציעים להוריד אפליקציה דרך קישור",
                      "Offers an app download through a link",
                      "אם רוצים את האפליקציה, חפשו אותה בעצמכם ב-Google Play או App Store.",
                      "If you want the app, search for it yourself in Google Play or the App Store."))

    for link in links:
        brand = _lookalike(link)
        if brand:
            add(_rule("lookalike_domain", VERY_STRONG,
                      f"הקישור ({link['host']}) מתחזה לאתר רשמי אבל אינו האתר האמיתי",
                      f"The link ({link['host']}) imitates an official site but isn't the real one",
                      "אתרי ממשלה בישראל מסתיימים ב-gov.il. היכנסו לאתר הרשמי בעצמכם, לא דרך הקישור.",
                      "Israeli government sites end in gov.il. Go to the official site yourself, not via the link."))
            break

    risky = [l for l in links if l["tld"] in _RISKY_TLDS]
    if risky:
        add(_rule("risky_domain_ending", STRONG,
                  f"הקישור מוביל לאתר בסיומת .{risky[0]['tld']}, שנפוצה באתרי הונאה",
                  f"The link goes to a .{risky[0]['tld']} site, a domain ending common in scams",
                  "אל תלחצו על הקישור.", "Don't open the link."))

    unfree = _FREE.sub(" ", text)
    if (_DEBT.search(unfree) or _PAY_ORDER.search(unfree)) and links:
        add(_rule("payment_via_link", STRONG,
                  "דורשים תשלום או הסדרת חוב דרך קישור",
                  "Asks you to pay or settle a debt through a link",
                  "אל תשלמו דרך קישור בהודעה. בדקו את החוב באתר או באפליקציה הרשמיים.",
                  "Don't pay through a message link. Check the debt on the official site or app."))

    small = [a for a in found["amounts"] if a["amount"] < 15 and a["currency"] in ("ILS", "USD")]
    if small and links:
        add(_rule("small_fee", STRONG,
                  f"מבקשים סכום קטן ({small[0]['text']}): כך משיגים את פרטי כרטיס האשראי",
                  f"Asks for a small amount ({small[0]['text']}): a common way to get card details",
                  "הסכום קטן, אבל פרטי הכרטיס שתקלידו ייגנבו.",
                  "The amount is small, but the card details you type will be stolen."))

    if _VERIFY.search(text) and (_VERIFY_WHAT.search(text) or _BLOCKED.search(text)):
        add(_rule("verify_details", STRONG,
                  "מבקשים לאמת או לעדכן פרטים אישיים",
                  "Asks you to verify or update personal details",
                  "גופים אמיתיים לא מבקשים לאמת פרטים דרך הודעה. התקשרו אליהם במספר הרשמי.",
                  "Real organizations don't ask you to verify details by text. Call their official number."))

    if _BLOCKED.search(text):
        add(_rule("threat", MEDIUM,
                  "מאיימים בחסימה, קנס או החזרת חבילה",
                  "Threatens a block, a penalty or a returned package",
                  "איום הוא דרך ללחוץ עליכם לפעול מהר. עצרו ובדקו.",
                  "Threats are meant to rush you. Stop and check."))

    if _URGENT.search(text):
        add(_rule("urgency", MEDIUM,
                  "לוחצים עליך לפעול מהר",
                  "Pressures you to act fast",
                  "אין סיבה למהר. הודעה אמיתית תחכה שתבדקו.",
                  "There's no need to hurry. A real message will wait while you check."))

    if _ENABLE_LINK.search(text):
        add(_rule("reply_to_enable_link", STRONG,
                  "מבקשים להשיב להודעה או להעתיק את הקישור ידנית, כדי לעקוף את החסימה של הטלפון",
                  "Asks you to reply or copy the link by hand, to get around your phone's link blocking",
                  "הטלפון חסם את הקישור כי השולח לא מוכר. אל תשיבו ואל תעתיקו אותו.",
                  "Your phone blocked the link because the sender is unknown. Don't reply or copy it."))

    unofficial = [l for l in links if l["domain"] not in _OFFICIAL_DELIVERY]
    if _DELIVERY.search(text) and _DELIVERY_PROBLEM.search(text) and unofficial:
        add(_rule("delivery_problem_link", STRONG,
                  "הודעה על בעיה במשלוח עם קישור לאתר שאינו של חברת השילוח הרשמית",
                  "A delivery problem with a link that isn't the official courier's site",
                  "בדקו משלוחים רק באתר או באפליקציה הרשמיים של דואר ישראל או חברת השליחויות.",
                  "Check deliveries only on the official Israel Post or courier site or app."))

    if _TOO_GOOD.search(text):
        add(_rule("too_good_to_be_true", STRONG,
                  "מבטיחים רווח או הכנסה גבוהים מדי",
                  "Promises unrealistic profits or income",
                  "אין רווח מובטח. קבוצות השקעה וג'ובים כאלה הם הונאה נפוצה.",
                  "No profit is guaranteed. Investment groups and jobs like this are a common scam."))

    if _MONEY_REQUEST.search(text):
        add(_rule("money_transfer_request", STRONG,
                  "מבקשים להעביר כסף",
                  "Asks you to transfer money",
                  "לפני שמעבירים כסף, התקשרו לאדם במספר המוכר לכם ושאלו.",
                  "Before sending money, call the person on the number you already know."))

    if _NEW_NUMBER.search(text):
        add(_rule("new_number", STRONG,
                  "מישהו טוען שהוא קרוב משפחה או חבר עם מספר חדש",
                  "Someone claims to be family or a friend with a new number",
                  "התקשרו למספר הישן של האדם ובדקו שזה באמת הוא.",
                  "Call the person's old number to check it's really them."))

    if _PRIZE.search(text):
        add(_rule("prize", STRONG,
                  "טוענים שזכית בפרס",
                  "Claims you won a prize",
                  "אם לא השתתפתם בהגרלה, לא זכיתם. אל תשלמו 'דמי טיפול'.",
                  "If you didn't enter, you didn't win. Don't pay any 'processing fee'."))

    if _OUR_RECORDS.search(text):
        add(_rule("claims_official_records", MEDIUM,
                  "טוענים שיש להם מידע עליך מרישומים רשמיים",
                  "Claims to have your details from official records",
                  "בדקו את הנושא ישירות מול הגוף הרשמי.",
                  "Check directly with the official body."))

    short = [l for l in links if l["host"] in _SHORTENERS]
    if short:
        add(_rule("shortened_link", MEDIUM,
                  f"קישור מקוצר ({short[0]['host']}) שמסתיר לאן הוא מוביל",
                  f"A shortened link ({short[0]['host']}) hides where it really goes",
                  "קישור מקוצר יכול להוביל לכל אתר. היזהרו.",
                  "A short link can lead anywhere. Be careful."))

    reassuring = []
    if links and all(_is_official_gov(l["host"]) or l["host"] in _APP_STORES for l in links):
        reassuring.append({"id": "official_links_only",
                           "he": "כל הקישורים מובילים לאתרים רשמיים (gov.il או חנויות אפליקציות)",
                           "en": "All links go to official sites (gov.il or app stores)"})
    return signs, reassuring
