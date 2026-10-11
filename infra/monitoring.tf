# Logging and monitoring, without message text or visitor addresses.
#
# The app writes one anonymous record per check (scam_detector/eventlog.py). Cloud Run's
# own request log would store every visitor's address for 30 days, so it is excluded.
# Cloud Run's built-in metrics (request counts, latency, instances) are not logs and
# keep working.

resource "google_project_service" "observability" {
  for_each           = toset(["logging.googleapis.com", "monitoring.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# --- Don't store Cloud Run's request log (it contains visitor addresses) ---------

resource "google_logging_project_exclusion" "cloud_run_requests" {
  name        = "exclude-cloud-run-request-logs"
  description = "Request logs hold visitor IP addresses; the app's own records hold none"
  filter      = "resource.type=\"cloud_run_revision\" AND log_id(\"run.googleapis.com/requests\")"
}

# --- Counters built from the app's anonymous records -----------------------------

locals {
  app_logs = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.app.name}\""
}

resource "google_logging_metric" "checks" {
  name        = "scam_detector/checks"
  description = "Checks, by result"
  filter      = "${local.app_logs} AND jsonPayload.event=\"check\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "risk_level"
      value_type = "STRING"
    }
  }
  label_extractors = { risk_level = "EXTRACT(jsonPayload.risk_level)" }
}

resource "google_logging_metric" "rate_limited" {
  name        = "scam_detector/rate_limited"
  description = "Checks refused by rate limiting, by limit"
  filter      = "${local.app_logs} AND jsonPayload.event=\"rate_limited\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "scope"
      value_type = "STRING"
    }
  }
  label_extractors = { scope = "EXTRACT(jsonPayload.scope)" }
}

resource "google_logging_metric" "check_failed" {
  name        = "scam_detector/check_failed"
  description = "Checks that failed with an error"
  filter      = "${local.app_logs} AND jsonPayload.event=\"check_failed\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# --- Email alerts -------------------------------------------------------------------

resource "google_monitoring_notification_channel" "email" {
  display_name = "Scam detector alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  depends_on   = [google_project_service.observability]
}

resource "google_monitoring_alert_policy" "errors" {
  display_name          = "Scam detector: checks failing"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "More than 3 checks failed in 5 minutes. Look at the check_failed records in Logs Explorer."
  }
  conditions {
    display_name = "check_failed > 3 in 5 min"
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.check_failed.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      duration        = "0s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }
      trigger {
        count = 1
      }
    }
  }
}

resource "google_monitoring_alert_policy" "abuse" {
  display_name          = "Scam detector: many rate-limited requests"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "More than 50 requests were refused by rate limiting in 10 minutes: someone may be abusing the app."
  }
  conditions {
    display_name = "rate_limited > 50 in 10 min"
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.rate_limited.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      duration        = "0s"
      aggregations {
        alignment_period     = "600s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }
      trigger {
        count = 1
      }
    }
  }
}

resource "google_monitoring_alert_policy" "slow" {
  display_name          = "Scam detector: checks are slow"
  combiner              = "OR"
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "The median response time stayed above 5 seconds for 15 minutes. (A single cold start takes ~20-30 s, so this uses the median over a long window.)"
  }
  conditions {
    display_name = "median latency > 5 s for 15 min"
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.app.name}\" AND metric.type=\"run.googleapis.com/request_latencies\""
      comparison      = "COMPARISON_GT"
      threshold_value = 5000
      duration        = "900s"
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_PERCENTILE_50"
        cross_series_reducer = "REDUCE_MAX"
      }
      trigger {
        count = 1
      }
    }
  }
}

# --- Dashboard -----------------------------------------------------------------------

resource "google_monitoring_dashboard" "main" {
  dashboard_json = jsonencode({
    displayName = "Scam detector"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width = 6, height = 4, xPos = 0, yPos = 0
          widget = {
            title = "Checks by result"
            xyChart = { dataSets = [{
              plotType = "STACKED_BAR"
              timeSeriesQuery = { timeSeriesFilter = {
                filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.checks.name}\""
                aggregation = { alignmentPeriod = "3600s", perSeriesAligner = "ALIGN_SUM",
                crossSeriesReducer = "REDUCE_SUM", groupByFields = ["metric.label.risk_level"] }
              } }
            }] }
          }
        },
        {
          width = 6, height = 4, xPos = 6, yPos = 0
          widget = {
            title = "Refused by rate limiting"
            xyChart = { dataSets = [{
              plotType = "STACKED_BAR"
              timeSeriesQuery = { timeSeriesFilter = {
                filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.rate_limited.name}\""
                aggregation = { alignmentPeriod = "3600s", perSeriesAligner = "ALIGN_SUM",
                crossSeriesReducer = "REDUCE_SUM", groupByFields = ["metric.label.scope"] }
              } }
            }] }
          }
        },
        {
          width = 6, height = 4, xPos = 0, yPos = 4
          widget = {
            title = "Response time (median and 95th percentile, ms)"
            xyChart = { dataSets = [
              { plotType = "LINE", legendTemplate = "median",
                timeSeriesQuery = { timeSeriesFilter = {
                  filter      = "metric.type=\"run.googleapis.com/request_latencies\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.app.name}\""
                  aggregation = { alignmentPeriod = "300s", perSeriesAligner = "ALIGN_PERCENTILE_50", crossSeriesReducer = "REDUCE_MAX" }
              } } },
              { plotType = "LINE", legendTemplate = "95th percentile",
                timeSeriesQuery = { timeSeriesFilter = {
                  filter      = "metric.type=\"run.googleapis.com/request_latencies\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.app.name}\""
                  aggregation = { alignmentPeriod = "300s", perSeriesAligner = "ALIGN_PERCENTILE_95", crossSeriesReducer = "REDUCE_MAX" }
              } } }
            ] }
          }
        },
        {
          width = 6, height = 4, xPos = 6, yPos = 4
          widget = {
            title = "Running copies of the app"
            xyChart = { dataSets = [{
              plotType = "LINE"
              timeSeriesQuery = { timeSeriesFilter = {
                filter      = "metric.type=\"run.googleapis.com/container/instance_count\" AND resource.labels.service_name=\"${google_cloud_run_v2_service.app.name}\""
                aggregation = { alignmentPeriod = "60s", perSeriesAligner = "ALIGN_MAX", crossSeriesReducer = "REDUCE_SUM" }
              } }
            }] }
          }
        },
      ]
    }
  })
  depends_on = [google_project_service.observability]
}
