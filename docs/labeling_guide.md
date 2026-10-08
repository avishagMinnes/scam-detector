# Labeling guide

Target: 100–200 messages, a mix of Hebrew and English, both scam and legitimate.
Aim for roughly half legitimate, including legitimate messages that *look* alarming
(real bank alerts, real delivery notices). Those are what cause false alarms.

## Columns in `data/labeled_messages.csv`
| Column | Values |
|--------|--------|
| `id` | Running number: `he-001`, `en-001`, ... |
| `text` | The message, anonymized (see below). Wrap in quotes if it has commas or line breaks |
| `language` | `he` / `en` / `mixed` |
| `label` | `scam` / `legit` |
| `scam_type` | From `docs/scam_types.md`; `none` for legit |
| `source` | `family`, `friend`, `uci_sms`, `cyber_directorate`, `self`, ... |
| `date_received` | Approximate, `YYYY-MM` is fine |
| `notes` | Why you labeled it this way, anything unclear |

## Anonymization (before a message enters the CSV)
- Ask permission from the person who received it
- Replace names with `[NAME]`, personal phone numbers with `[PHONE]`, ID numbers with `[ID]`,
  account and card numbers with `[ACCOUNT]`, home addresses with `[ADDRESS]`
- **Keep** the scammer's links, domains and sender numbers: they are the signal
- Keep the original spelling and mistakes: they are a signal too
- The raw original goes in `data/raw/` only (git-ignored), or nowhere

## When unsure
Label it the way you'd advise a family member, and explain in `notes`.
If you can't decide, leave it out of the test set.

## Draft (synthetic) examples
`data/draft_examples.csv` holds examples I wrote myself, based on real warnings. They are
for practice and prompt-writing, **not** for the test set: accuracy measured on messages
you wrote yourself will look better than it really is. Only real collected messages go into
`labeled_messages.csv`. The domains in the drafts are made up, so don't visit them.

## Marketing, political and illegal-sales messages
- Unwanted marketing and political messages are `legit`: annoying is not the same as a scam.
  They are good examples of normal traffic and help measure false alarms.
- `unsure` is only allowed in review files. Decide each one before it goes into
  `labeled_messages.csv`, or leave it out.
