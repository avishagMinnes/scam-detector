"""Build data/web_examples.csv: real scam messages quoted verbatim in published warnings.

Collected 2026-10-11 by searching Israeli news sites, official warnings and consumer
sites; only messages the source quotes word for word. TRAINING ONLY: famous published
campaigns don't represent what people actually receive, so they never enter the test set.

Any candidate too similar to a message already in labeled_messages.csv is dropped, so a
published copy of a test message can't leak into training.
"""
import sys
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scam_detector.classifier import clean_text  # noqa: E402

OUT = ROOT / "data" / "web_examples.csv"
MAX_SIMILARITY = 0.5

# (text, language, scam_type, source_url, published)
CANDIDATES = [
    # --- banks and credit cards
    ("לקוח יקר, זיהינו פעילות חריגה בחשבונך על מנת לאבטח את חשבונך מחדש יש להתחבר בלינק הבא: https://hapoalim-bank.com",
     "he", "bank_impersonation", "https://www.ice.co.il/digital-140/news/article/929159", "2023-01"),
    ("שלום אדוני. קיימת פעילות חשודה בחשבונך. היכנס עכשיו כדי לאשר את החשבון",
     "he", "bank_impersonation", "https://www.ynet.co.il/articles/0,7340,L-5556536,00.html", "2019-07"),
    ("חשבונך נחסם זמנית. לשחרור החסימה יש להכנס מחדש לחשבון",
     "he", "bank_impersonation", "https://www.ynet.co.il/articles/0,7340,L-5032065,00.html", "2017-10"),
    ('חשבונך יוגבל בתוך 48 שעות, אנא היכנסו ללינק המצו"ב',
     "he", "bank_impersonation", "https://www.kikar.co.il/internet-and-computers/367110", "2020-07"),
    ("אנא אשרו את נתוני האשראי שלכם מטעמי אבטחה",
     "he", "bank_impersonation", "https://www.ynet.co.il/economy/article/bjxxlegcf", ""),
    ("שלום, מדברים מחברת CAL. זיהינו פעילות חשודה בכרטיס שלך. למען ביטחונך השענו זמנית את השימוש בכרטיס האשראי שלך. עליך לאמת את זהותך כדי שהכרטיס לא ייחסם לצמיתות.",
     "he", "bank_impersonation", "https://www.ice.co.il/consumerism/news/article/1050121", "2025-02"),
    # --- deliveries
    ("החבילה שלך בדואר ישראל הגיעה למחסן אך נחשבת לא ניתנת למסירה עקב פרטי כתובת לא ברורים. נא לאשר את הכתובת בקישור תוך 12 שעות. (תשובה Y. לאחר מכן עצור את ה-SMS ופתח מחדש את קישור הפעלת ה-SMS, או העתק את הקישור ל-Safari ופתח אותו) צוות דואר ישראל מאחל לכם חיים מאושרים!",
     "he", "delivery", "https://www.mako.co.il/nexter-news/Article-98a879a77183e81026.htm", "2024-03"),
    ("החבילה שלך הגיעה למחסן שלנו ולא ניתן לשלוח אותה בגלל פרטי כתובת שגויים, אנא מלא שוב את פרטי הכתובת המדויקים, אנו נשלח אותה תוך 24 שעות. (אנא השב ץ, ואז צא מהודעת הטקסט, פתח מחדש את קישור הפעלת הודעת הטקסט, או העתק את הקישור לדפדפן Safari כדי לפתוח אותו) שיהיה לך יום נהדר!",
     "he", "delivery", "https://www.mako.co.il/nexter-news/Article-b30b67eec6ce691026.htm", "2025-05"),
    ("אנא קבע מועד חדש לאיסוף או מסור כתובת אחרת בלינק",
     "he", "delivery", "https://www.mako.co.il/nexter-news/Article-b30b67eec6ce691026.htm", "2025-05"),
    ("כתובת החבילה שלך שגויה, אנא אשר את הכתובת",
     "he", "delivery", "https://www.ice.co.il/digital-140/news/article/970604", "2023-07"),
    ("חבילה שלך עצר במכס, אתה צריך לשלם 6.21 שקלים, לשחרר מכס",
     "he", "delivery", "https://www.ice.co.il/digital-140/news/article/970604", "2023-07"),
    ("קונה יקר, המשלוח צריך שתאשר את פרטי המשלוח למשלוח בהקדם. חשוב אם לא תאשר את המידע, המשלוח יוחזר וכספך יוחזר. לאישור המידע לחץ כאן",
     "he", "delivery", "https://tech.walla.co.il/item/3496988", "2022-03"),
    ("לקוח יקר, אנו מצטערים להודיע לך שהחבילה שלך תישלח חזרה, זה עלול לקרות כאשר כתובת המקבל שגויה. אנא שלם מכס (14.99 ₪) כדי להגיש בקשה למשלוח מחדש עבור חבילה זו, מלא את הטופס באתר שלנו",
     "he", "delivery", "https://www.ice.co.il/digital-140/news/article/927062", "2023-01"),
    # --- government, police, fines
    ("לקוח יקר, זיהינו כי אחד מאמצעי התשלום שלך אינו בתוקף. יש לעדכן באתרינו את אמצעי התשלום כדי להימנע מהליכי הוצאה לפועל, ופיגור ריביות",
     "he", "government_impersonation", "https://www.ice.co.il/digital-140/news/article/927062", "2023-01"),
    ("שלום [NAME], בהתאם לבדיקה שנערכה במאגר הביטוח הלאומי, נמצא כי הנך זכאית להחזר בסכום של 741.09 שקל.",
     "he", "government_impersonation", "https://www.maariv.co.il/economy/consumerism/article-1171395", "2025-02"),
    ("יש לך הפרת תנועה, אנא טפל בזה בהקדם",
     "he", "government_impersonation", "https://www.ice.co.il/law/news/article/1083185", "2025-09"),
    ("תשלום הכניסה לכביש לא ערב, אנא נסה שוב",
     "he", "government_impersonation", "https://www.ice.co.il/consumerism/news/article/976450", "2023-08"),
    ("הובא לידיעתנו כי צפית בחומרים המציגים קטינים המעורבים בפעילות מינית מפורשת",
     "he", "government_impersonation", "https://br7news.co.il/he/news/news-1791371038", "2026-10"),
    # --- utilities and services
    ("שלום רב. קיים חוב חייב להסדיר מיידית בחברת החשמל. לתשלום",
     "he", "service_impersonation", "https://www.ice.co.il/consumerism/news/article/837818", "2021-12"),
    ("המרשם הרפואי יעלה מעתה 2 שקלים ולחצו כאן כדי לשלם",
     "he", "other", "https://tech.walla.co.il/item/3315911", "2019-10"),
    # --- WhatsApp takeover and family impersonation
    ("בוקר טוב למי יש בנק פועלים או לאומי דיסנקוט ויכול לעשות לי טובה קטנה",
     "he", "family_impersonation", "https://www.mako.co.il/nexter-news/Article-e9ba96728593c81026.htm", "2023-12"),
    ("היי ממי, מה נשמע? פתחתי קבוצה רק למפוני העוטף, ככה תדעי שזה מגיע לידיים הנכונות",
     "he", "family_impersonation", "https://www.mako.co.il/nexter-news/Article-e9ba96728593c81026.htm", "2023-12"),
    ("שלום, אני מצטער ששלחתי לך קוד בן 6 ספרות בטעות. אתה יכול בבקשה לשלוח לי אותו? זה דחוף",
     "he", "account_security", "https://www.israelhayom.co.il/article/834315", "2020-12"),
    ("Hello mum, I've broken my phone and I'm using a friends old one. I need to talk its urgent can you text me on WhatsApp on my new number please.",
     "en", "family_impersonation", "https://www.which.co.uk/news/article/notorious-hi-mum-and-dad-scam-spreads-from-whatsapp-to-text-message-an7N34c0gVbP", "2022-09"),
    ("Hi mum I'm texting you off a friends phone I've smashed mine and their phones about to die, can you WhatsApp my new number please.",
     "en", "family_impersonation", "https://www.which.co.uk/news/article/notorious-hi-mum-and-dad-scam-spreads-from-whatsapp-to-text-message-an7N34c0gVbP", "2022-09"),
    ("Hey Mum it's me. I got a new phone number, you can delete the old one. I got a new phone. I'm still transferring everything",
     "en", "family_impersonation", "https://australianmutual.bank/news-blog/articles/scam-targeting-parents/", "2022-08"),
    ("The banking app has put a 48-hour security on the app due to fraud. All nice but I have to pay two payments",
     "en", "family_impersonation", "https://australianmutual.bank/news-blog/articles/scam-targeting-parents/", "2022-08"),
    ("Hi Mum, please ring me on 07871412538 as I've dropped my phone and shattered the screen.",
     "en", "family_impersonation", "https://www.johnogroat-journal.co.uk/news/watten-woman-warns-of-hi-mum-text-scam-324468/", "2023-08"),
    ("Hi mum, it's your favourite daughter",
     "en", "family_impersonation", "https://www.khaleejtimes.com/business/tech/hey-mum-whatsapp-scammers-dupe-parents-while-posing-as-their-children?amp=1", "2022-08"),
    # --- investment
    ("מאשר שבשבוע הבא נתחיל את תוכנית ההשקעה הסופר-500%. הערב אסביר לכם כמה פרטים תפעוליים כדי שנוכל להשיג רווחים מעבר לציפיות בצורה בטוחה יותר, ולהגשים את היעד הראשון של חברי הצוות החדשים - להרוויח מספיק לכיסוי הוצאות המשפחה ל-30 השנים הבאות. בדרך ההשקעה אנו דומים לצבא היוצא לקרב - חייבים אסטרטגיה שלמה וכללים ברורים כדי לנצח שוב ושוב בשדה ההשקעות. אם אתם ניגשים בגישה של 'לנסות', הרווח של כמה מאות או אלפי דולרים לא ישנה את מצב חייכם. לכן, מי שאינו מוכן להשקיע את מלוא המאמץ ולהיצמד לתוכנית - לא מומלץ שיצטרף",
     "he", "investment", "https://www.ice.co.il/finance/news/article/1118637", "2026-06"),
    ("היום הוא היום האחרון להגדלת הפוזיציה, משום שביום שישי צפויה עלייה של יותר מ-50%. ניתן לנצל את כל ההון הזמין כדי להשיג רווחים בטווח הקצר ברמת ודאות גבוהה. ייתכן שיהיה צורך להמתין לפחות שנה להזדמנות דומה",
     "he", "investment", "https://www.ice.co.il/finance/news/article/1118637", "2026-06"),
    ("המניה שנבנה בה פוזיציה בשבוע הבא נסחרת כעת סביב 2 דולר. בהמשך היא צפויה לעלות עד 9 דולר",
     "he", "investment", "https://www.ice.co.il/finance/news/article/1118637", "2026-06"),
    ("כל מי שקנה את Cuprina Holdings (סימול: CUPR) כבר הרוויח בערך 24%!",
     "he", "investment", "https://finance.walla.co.il/item/3775825", "2025-08"),
    ("Hi [NAME], I'm Vicky Ho. Don't you remember me?",
     "en", "investment", "https://www.npr.org/transcripts/1253043749", "2025-05"),
    # --- prizes and jobs
    ("Oi mate, your Coles rewards points are on the blink. Get em' redeemed before they vanish",
     "en", "prize", "https://www.thesenior.com.au/story/8630845/police-warn-of-coles-supermarket-scam-targeting-the-vulnerable", "2024-05"),
    ("LIDL is giving away free grocery worth £175 to everyone this week to support the nation during the Corona Pandemic. Get your voucher: http://www.lidl.uk-helping.club",
     "en", "prize", "https://www.lovemoney.com/news/95824/coronavirus-fake-lidl-voucher-free-grocery-offer-pandemic-twitter-facebook-whatsapp", "2020-05"),
    ("Hi there! Sorry to interrupt. I'm from Indeed. We're currently recruiting remote product testers (U.S.-based). This role lets you earn $50–$400 per day by spending just 60–120 minutes daily testing and reviewing new products or services online.",
     "en", "job_offer", "https://slate.com/technology/2025/08/indeed-job-recruiter-text-message-scam.html", "2025-08"),
]


def main():
    cand = pd.DataFrame(CANDIDATES, columns=["text", "language", "scam_type", "source", "date_received"])
    existing = pd.read_csv(ROOT / "data" / "labeled_messages.csv", encoding="utf-8-sig")
    split = pd.read_csv(ROOT / "data" / "split.csv")
    existing = existing.merge(split, on="id", how="left")

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
    vec.fit(pd.concat([cand.text, existing.text]).map(clean_text))
    sim = cosine_similarity(vec.transform(cand.text.map(clean_text)),
                            vec.transform(existing.text.map(clean_text)))
    best = sim.argmax(axis=1)
    keep = []
    for i, r in cand.iterrows():
        s, j = sim[i, best[i]], best[i]
        if s >= MAX_SIMILARITY:
            print(f"DROP (similar {s:.2f} to {existing.id[j]}, {existing.split[j]}): {r.text[:50]}")
        else:
            keep.append(i)

    out = cand.loc[keep].reset_index(drop=True)
    out.insert(0, "id", [f"{l}-web{n:03d}" for n, l in enumerate(out.language, 1)])
    out["label"] = "scam"
    out["notes"] = "quoted verbatim in a published warning"
    out = out[["id", "text", "language", "label", "scam_type", "source", "date_received", "notes"]]
    out.to_csv(OUT, index=False, encoding="utf-8-sig")
    print(f"\nSaved {len(out)} of {len(cand)} to {OUT}")
    print(out.groupby(["scam_type", "language"]).size().unstack(fill_value=0))


if __name__ == "__main__":
    main()
