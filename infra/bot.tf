# The Telegram bot: a second Cloud Run service from the same image (APP_MODULE=bot:app).
#
# Telegram must reach it, so it is public, but bot.py refuses every request without the
# webhook secret below. The web app (scam-detector) stays private.
# The bot's own Telegram token is never stored in the cloud: replies go back inside
# Telegram's webhook request, and setWebhook is called once from your computer
# (deploy\set_webhook.ps1).

resource "google_project_service" "secrets" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

# Random secret Telegram sends with every update (not the bot token)
resource "random_password" "webhook_secret" {
  length  = 48
  special = false
}

resource "google_secret_manager_secret" "webhook_secret" {
  secret_id = "telegram-webhook-secret"
  replication {
    auto {}
  }
  depends_on = [google_project_service.secrets]
}

resource "google_secret_manager_secret_version" "webhook_secret" {
  secret      = google_secret_manager_secret.webhook_secret.id
  secret_data = random_password.webhook_secret.result
}

# The app account may read this one secret, nothing else
resource "google_secret_manager_secret_iam_member" "runtime_reads_webhook_secret" {
  secret_id = google_secret_manager_secret.webhook_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_cloud_run_v2_service" "bot" {
  name     = "scam-detector-bot"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    max_instance_request_concurrency = 4
    timeout                          = "60s"
    service_account                  = google_service_account.runtime.email

    containers {
      # First creation uses the app's current image; deployments then update it
      image = google_cloud_run_v2_service.app.template[0].containers[0].image
      ports {
        container_port = 8080
      }
      env {
        name  = "APP_MODULE"
        value = "bot:app"
      }
      env {
        name  = "TELEGRAM_ALLOWED_USERS"
        value = join(",", var.telegram_allowed_users)
      }
      env {
        name = "TELEGRAM_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.webhook_secret.secret_id
            version = "latest"
          }
        }
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image, client, client_version]
  }

  depends_on = [google_secret_manager_secret_iam_member.runtime_reads_webhook_secret]
}

# Public, so Telegram can call the webhook (bot.py checks the secret on every request)
resource "google_cloud_run_v2_service_iam_member" "bot_public" {
  name     = google_cloud_run_v2_service.bot.name
  location = google_cloud_run_v2_service.bot.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# GitHub Actions may update the bot too
resource "google_cloud_run_v2_service_iam_member" "deployer_update_bot" {
  name     = google_cloud_run_v2_service.bot.name
  location = google_cloud_run_v2_service.bot.location
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

output "bot_webhook_url" {
  value = "${google_cloud_run_v2_service.bot.uri}/telegram/webhook"
}
