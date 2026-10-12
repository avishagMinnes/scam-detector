# Phase 6 analytics: saved queries (views) over the anonymous records in BigQuery.
# A Looker Studio dashboard connects to these views.
#
# Weekly totals only, never single checks: with a handful of users, finer detail could
# hint at who checked what and when. Before publishing any figure, check that its count
# isn't tiny (e.g. under 5).

locals {
  records = "`${var.project_id}.${google_bigquery_dataset.events.dataset_id}.run_googleapis_com_stdout`"

  # Rough scam type from the warning signs (first match wins). The records hold sign ids,
  # not message text, so this is how the dashboard can say what people are receiving.
  scam_type_sql = <<-SQL
    CASE
      WHEN EXISTS (SELECT 1 FROM UNNEST(jsonPayload.signs) s WHERE s IN ('new_number', 'money_transfer_request')) THEN 'family / Hi Mom'
      WHEN 'asks_for_code' IN UNNEST(jsonPayload.signs) THEN 'code request (account takeover)'
      WHEN 'too_good_to_be_true' IN UNNEST(jsonPayload.signs) THEN 'investment / job'
      WHEN 'prize' IN UNNEST(jsonPayload.signs) THEN 'prize / gift'
      WHEN 'delivery_problem_link' IN UNNEST(jsonPayload.signs) THEN 'delivery'
      WHEN EXISTS (SELECT 1 FROM UNNEST(jsonPayload.signs) s WHERE s IN ('payment_via_link', 'claims_official_records', 'small_fee')) THEN 'debt / fine / payment'
      WHEN 'verify_details' IN UNNEST(jsonPayload.signs) THEN 'bank / account verification'
      WHEN 'install_from_link' IN UNNEST(jsonPayload.signs) THEN 'malicious app'
      WHEN EXISTS (SELECT 1 FROM UNNEST(jsonPayload.signs) s WHERE s IN ('lookalike_domain', 'mixed_alphabet', 'risky_domain_ending')) THEN 'fake website (other)'
      ELSE 'other'
    END
  SQL
}

resource "google_bigquery_table" "checks_weekly" {
  dataset_id          = google_bigquery_dataset.events.dataset_id
  table_id            = "checks_weekly"
  description         = "Checks per week, by channel, language and result"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT DATE_TRUNC(DATE(timestamp), WEEK(SUNDAY)) AS week,
             jsonPayload.channel AS channel,
             jsonPayload.language AS language,
             jsonPayload.risk_level AS result,
             COUNT(*) AS checks
      FROM ${local.records}
      WHERE jsonPayload.event = 'check'
      GROUP BY week, channel, language, result
    SQL
  }
}

resource "google_bigquery_table" "scam_types_weekly" {
  dataset_id          = google_bigquery_dataset.events.dataset_id
  table_id            = "scam_types_weekly"
  description         = "Messages flagged as scam or suspicious per week, by rough scam type"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT DATE_TRUNC(DATE(timestamp), WEEK(SUNDAY)) AS week,
             ${local.scam_type_sql} AS scam_type,
             COUNT(*) AS checks
      FROM ${local.records}
      WHERE jsonPayload.event = 'check' AND jsonPayload.risk_level IN ('high', 'medium')
      GROUP BY week, scam_type
    SQL
  }
}

resource "google_bigquery_table" "signs_weekly" {
  dataset_id          = google_bigquery_dataset.events.dataset_id
  table_id            = "signs_weekly"
  description         = "How often each warning sign fired per week (the scam tricks people meet)"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT DATE_TRUNC(DATE(timestamp), WEEK(SUNDAY)) AS week,
             sign,
             COUNT(*) AS times
      FROM ${local.records}, UNNEST(jsonPayload.signs) AS sign
      WHERE jsonPayload.event = 'check' AND sign != 'model_score'
      GROUP BY week, sign
    SQL
  }
}

resource "google_bigquery_table" "feedback_weekly" {
  dataset_id          = google_bigquery_dataset.events.dataset_id
  table_id            = "feedback_weekly"
  description         = "👍/👎 per week by the result people rated: where the detector is wrong"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT DATE_TRUNC(DATE(timestamp), WEEK(SUNDAY)) AS week,
             jsonPayload.risk_level AS result_rated,
             COUNTIF(jsonPayload.verdict = 'correct') AS thumbs_up,
             COUNTIF(jsonPayload.verdict = 'wrong') AS thumbs_down,
             CASE jsonPayload.risk_level
               WHEN 'low' THEN 'possible missed scam'
               ELSE 'possible false alarm'
             END AS what_thumbs_down_means
      FROM ${local.records}
      WHERE jsonPayload.event = 'feedback'
      GROUP BY week, result_rated
    SQL
  }
}

resource "google_bigquery_table" "signs_in_wrong_answers" {
  dataset_id          = google_bigquery_dataset.events.dataset_id
  table_id            = "signs_in_wrong_answers"
  description         = "For each warning sign: how often answers showing it got 👍 vs 👎 (all time)"
  deletion_protection = false
  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT sign,
             COUNTIF(jsonPayload.verdict = 'correct') AS thumbs_up,
             COUNTIF(jsonPayload.verdict = 'wrong') AS thumbs_down,
             SAFE_DIVIDE(COUNTIF(jsonPayload.verdict = 'wrong'), COUNT(*)) AS share_wrong
      FROM ${local.records}, UNNEST(jsonPayload.signs) AS sign
      WHERE jsonPayload.event = 'feedback'
      GROUP BY sign
    SQL
  }
}
