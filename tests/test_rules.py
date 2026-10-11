from scam_detector.rules import check


def ids(text):
    signs, _ = check(text)
    return {s["id"] for s in signs}


# --- scams that must be caught --------------------------------------------

def test_whatsapp_code_request():
    assert "asks_for_code" in ids("היי, שלחתי לך בטעות קוד של 6 ספרות. זה דחוף, תוכל לשלוח לי אותו?")


def test_lookalike_government_domain():
    assert "lookalike_domain" in ids("כדי לקבל פיצויי המלחמה רשמו באתר הזה https://taxesgov.net/he")
    assert "lookalike_domain" in ids("לצפייה בתיק ותשלום : https://govvee.vu/gevose")


def test_lookalike_brand_domain():
    assert "lookalike_domain" in ids("Please click here https://shein.top/apaq14q")
    assert "lookalike_domain" in ids("דואר ישראל: https://israelpost-track.top/il")


def test_risky_domain_ending_and_small_fee():
    found = ids("לחידוש החבילה בעלות מבצע של 2.50 שקלים: https://ilpay.ru/x8me1s")
    assert {"risky_domain_ending", "small_fee"} <= found


def test_debt_payment_link():
    assert "payment_via_link" in ids("קיימת חוב בגין נסיעות בכביש 6. להסדרת התשלום: did.li/Route6")


def test_fake_delivery_notice():
    assert "delivery_problem_link" in ids("סטטוס משלוח: IL123 נעצר - ראה עוד mvnkd.info/Sxq8W6J")
    assert "delivery_problem_link" in ids("Your package could not be delivered: https://usps-redelivery-info.com")


def test_install_app_from_link():
    assert "install_from_link" in ids("פיקוד העורף: יש להתקין את העדכון לאפליקציה: https://oref-update.app/download")


def test_hi_mom():
    found = ids("היי אמא, זה המספר החדש שלי, הטלפון נפל לי למים. אני צריך להעביר תשלום דחוף")
    assert {"new_number", "money_transfer_request"} <= found


def test_bank_verify_without_link():
    assert "verify_details" in ids("התראה: בוצעה בקשה להעברת כספים. אם לא ביצעת את הפעולה, יש לאמת את זהותך באופן מיידי.")


def test_investment_group():
    assert "too_good_to_be_true" in ids("87% מהמשתתפים הרוויחו מעל 30% בחודש האחרון")


def test_reply_to_enable_link():
    assert "reply_to_enable_link" in ids('יש להשיב "1" ולפתוח מחדש את ההתראה, או להעתיק את הקישור ידנית לדפדפן')
    assert "reply_to_enable_link" in ids('(השב "כן" כדי להזין כתובת חדשה, או העתק והדבק את הקישור')
    assert "reply_to_enable_link" in ids("Reply Y to activate the link")


def test_court_and_license_threats():
    found = ids("התיק יועבר לבית המשפט ורישיון הנהיגה שלך עלול להיות מוגבל. מועד אחרון לתשלום: היום")
    assert {"threat", "urgency"} <= found


# --- real messages that must NOT get warning signs ------------------------

def test_payment_demands_still_caught():
    assert "payment_via_link" in ids("קיים חוב פתוח על שמך, להסדרת החוב: https://pay-now.xyz")
    assert "payment_via_link" in ids("נותר לתשלום קנס חנייה https://fines.example.com")
    assert "payment_via_link" in ids("יש לשלם את היתרה עד הערב https://example.com/p")
    assert "payment_via_link" in ids("Please pay the outstanding amount: https://example.com/p")


def test_marketing_that_mentions_payment():
    assert "payment_via_link" not in ids("אפשר לשלם בכל אמצעי התשלום באתר https://shop.example.co.il")
    assert "payment_via_link" not in ids("Pay the balance in 12 monthly installments. https://shop.example.com")
    assert "payment_via_link" not in ids("התשלום שלך התקבל, תודה! לקבלה: https://shop.example.co.il/r")


def test_app_invitation_is_only_medium():
    signs, _ = check("האפליקציה החדשה שלנו כבר כאן! הורידו עכשיו https://example.co.il/app")
    found = {s["id"]: s["strength"] for s in signs}
    assert found.get("app_download_link") == "medium"
    assert "install_from_link" not in found


def test_required_update_is_strong():
    found = ids("עדכון אבטחה חובה לאפליקציית הבנק. יש להתקין את הגרסה כדי להמשיך: https://example.app/apk")
    assert "install_from_link" in found


def test_opt_out_reply_is_not_link_trick():
    assert "reply_to_enable_link" not in ids("להסרה השב 1 ל 0529999688")
    assert "reply_to_enable_link" not in ids("לשיחה עם נציג השב 1 להסרה השב 2")



def test_real_code_sms_says_dont_share():
    assert "asks_for_code" not in ids("קוד האימות שלך הוא 482913. אין למסור את הקוד לאף אחד, כולל נציגי הבנק.")
    assert "asks_for_code" not in ids("Your WhatsApp code: 255-198. Do not share this code with anyone")


def test_hebrew_word_fragments():
    # "אקדמי " contains "דמי " (fee); "רחוב" contains "חוב" (debt)
    assert "payment_via_link" not in ids("מסע אקדמי שונה, הצטרפו אלינו https://amit.org.il/amitim/")
    assert "payment_via_link" not in ids("הסניף ברחוב הרצל https://example.co.il/branch")


def test_free_check_is_not_a_payment():
    assert "payment_via_link" not in ids("בדיקה ללא תשלום מראש https://f4u.biz/a-5")


def test_mentioning_gift_card_is_not_a_money_request():
    assert "money_transfer_request" not in ids("קיבלת גיפטקארד סלולרי למימוש בלמעלה מ-100 רשתות http://bl2.co/P41")


def test_real_israel_post_notice():
    assert "delivery_problem_link" not in ids("דואר ישראל: דבר דואר ממתין לך בסניף עד 15/10. לפרטים: israelpost.co.il")


def test_official_gov_link_is_reassuring():
    signs, reassuring = check("לקביעת תור בלשכה: http://go.gov.il/zimuntor")
    assert "lookalike_domain" not in {s["id"] for s in signs}
    assert [r["id"] for r in reassuring] == ["official_links_only"]


def test_every_sign_has_both_languages():
    signs, _ = check("זכית! שלם 4.90 ש\"ח דחוף https://bit.ly/x https://paypa1-gov.ru/a חבילה נעצרה")
    assert len(signs) >= 5
    for s in signs:
        assert s["he"] and s["en"] and s["advice_he"] and s["advice_en"]
