# Israel National Cyber Directorate: scam warnings (summary)

Compiled 2026-10-08 from press coverage of the Directorate's public warnings.
Read the originals on gov.il before relying on this.

## 1. Fake Israel Post delivery notices → `delivery`
- SMS says a delivery failed and asks you to "update or confirm your address".
- The link opens a near-perfect copy of the Israel Post tracking site.
- **Key detail:** the fake page sends what you type to the attackers *as you type it*.
  Leaving before pressing "send" doesn't protect you.
- Advice: track parcels only on the official Israel Post site or app. Don't click delivery
  links you weren't expecting.

## 2. Government impersonation: Highway 6 / GOV.IL debts → `government_impersonation`
- SMS demands payment of a "debt" (e.g. Highway 6 tolls) with a link to a fake payment site.
- On some phones the fake SMS **appears inside the real GOV.IL message thread**. This is a
  quirk of how phones group SMS sender names, not a breach of GOV.IL.
- Detection lesson: **sender name is not proof.** Judge the link and the request, not the sender.
- Advice: never enter ID, personal or card details on a site reached from an SMS link.

## 3. Fake emergency (Pikud HaOref) alerts → `government_impersonation` (malware)
- SMS impersonating the Home Front Command alert app asks you to install an "update"
  from a shortened link. It installs Android spyware (location, SMS, contacts).
- Related: fake panic messages ("avoid shelters"), meant to scare, not to steal.
- Detection lesson: any request to **install an app from a link** is high risk.

## 4. WhatsApp account takeover → `account_security`, then `family_impersonation`
- The attacker registers *your* number on their device, so WhatsApp texts *you* a code.
- They then message you ("I sent you a code by mistake, it's urgent, send it back").
- With your account, they message your contacts and groups asking for urgent money transfers.
- Advice: **never share a verification code**, with anyone, ever.

## 5. Bank / support impersonation → `bank_impersonation`
- Banks and real companies never ask you to share a code, share your screen, or install
  remote-control apps. Any of these is a clear warning sign.

## 6. Investment groups → `investment`
- Links to WhatsApp "stock tips" groups, in Hebrew and English, that end in requests for
  personal details and money.

## 7. Hostile influence messages → `other`
- Mass SMS from Iranian actors (recruitment offers, threats). Not financial fraud, but a
  detector should still flag them.

## General advice from the Directorate
Ignore suspicious messages, block the sender, don't forward them, don't click links,
don't enter details.

## What this means for the detector
| Signal | Weight |
|--------|--------|
| Request for a verification code | Very strong |
| Request to install an app from a link | Very strong |
| Payment request via link (small "fee", "debt") | Strong |
| Link domain doesn't match the claimed organization | Strong |
| Shortened link (bit.ly etc.) | Medium |
| Sender name matches a real organization | **Not a trust signal** (can be spoofed) |

## Sources
- [Maariv: Israel Post phishing](https://www.maariv.co.il/economy/tech/article-1350067)
- [Srugim: Highway 6 warning](https://www.srugim.co.il/101004347-שימו-לב-מערך-הסייבר-מזהיר-מהודעות-מתחזות-על-כביש-6)
- [Israel National News: GOV.IL thread spoofing](https://israelnationalnews.com/flashes/689709)
- [Rankiteo: Oref spyware](https://blog.rankiteo.com/isrore1772829825-oref-alert-israel-national-cyber-directorate-cyber-attack-march-2026/)
- [Ynet: fake shelter warning](https://www.ynetnews.com/article/cfzi4kmq4)
- [Ynet: Iranian SMS](https://www.ynetnews.com/article/9h32ckpiz)
- [ESET Israel: WhatsApp scams](https://www.eset.com/il/blog/home/scams/top-whatsapp-scams/)
- [Ynet: phishing topic (investment groups)](https://www.ynetnews.com/topics/Phishing)
