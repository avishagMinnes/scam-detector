# Scam types

Every scam message gets one `scam_type` from this list. Legitimate messages use `none`.

| scam_type | Description | Typical red flags |
|-----------|-------------|-------------------|
| `delivery` | Fake parcel or customs notice (Israel Post, DHL, UPS) | Small "fee" to release a package, short or lookalike link, urgency |
| `bank_impersonation` | Pretends to be a bank, credit card company or payment app | "Your account is blocked", asks for a login, card details or OTP code |
| `family_impersonation` | "Hi Mom, I lost my phone" / new-number scams | Unknown number claiming to be a relative, quick move to an urgent money transfer |
| `investment` | Fake trading, crypto or "guaranteed returns" | Unrealistic profits, celebrity endorsement, pressure to move to WhatsApp or Telegram |
| `prize` | You won a lottery, gift or voucher | You never entered, a "processing fee" is needed, personal details requested |
| `government_impersonation` | Tax authority, National Insurance, police, fines | Threat of penalties, payment link, odd sender |
| `account_security` | Fake password reset or login alert (Google, Microsoft, WhatsApp) | Asks you to share a verification code, lookalike domain |
| `job_offer` | Easy remote work, "like videos for money" | Pay that is too good, upfront fee, request for ID documents |
| `service_impersonation` | Pretends to be a mobile carrier, streaming service or utility | Plan "expires today", tiny renewal price to get card details, foreign or lookalike payment domain |
| `financial_offer` | Fake loans, tax refunds, mortgage "refunds", pension withdrawal | Sounds governmental ("dear citizen", "state-backed"), generic domain, deadline, "free check" |
| `other` | Scam that doesn't fit above | Explain in `notes` |
| `none` | Legitimate message | |

## Cross-cutting red flags (input for the LLM prompt in Phase 2)
- Urgency or threats ("within 24 hours", "your account will be closed")
- Requests for codes, passwords, card numbers or ID numbers
- Requests for payment, especially gift cards, crypto or transfers to private accounts
- Links: shortened URLs, lookalike domains (`paypa1.com`), newly registered domains
- Sender does not match the claimed organization
- Moving the conversation to another app

## Sources to read
- Israel National Cyber Directorate: public scam warnings (gov.il)
- Bank of Israel / Israeli banks: fraud warning pages
- UK NCSC and US FTC consumer alerts (English examples)
- UCI SMS Spam Collection (English dataset)
