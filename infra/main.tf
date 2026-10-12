# The scam detector's Google Cloud setup, as code.
#
# Run through infra\tf.ps1 (signs in with the personal "scam-detector" gcloud
# configuration, never the default credentials):
#   powershell -File infra\tf.ps1 plan
#   powershell -File infra\tf.ps1 apply
#
# Not managed here (done by hand, once): the project itself, the billing account link,
# and the $5 budget alert. Budgets only alert; the free trial is the real spending cap.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# --- APIs --------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each           = toset(["run.googleapis.com", "artifactregistry.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# --- Image storage -------------------------------------------------------------

resource "google_artifact_registry_repository" "images" {
  repository_id = "scam-detector"
  location      = var.region
  format        = "DOCKER"
  description   = "Scam detector images"

  # Keep only the 2 newest images, so storage stays around one image (~1 GB)
  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "keep-2-newest"
    action = "KEEP"
    most_recent_versions {
      keep_count = 2
    }
  }
  cleanup_policies {
    id     = "delete-older"
    action = "DELETE"
    condition {
      tag_state = "ANY"
    }
  }

  depends_on = [google_project_service.apis]
}

# --- The app ---------------------------------------------------------------------

resource "google_cloud_run_v2_service" "app" {
  name     = "scam-detector"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # reachable, but every request needs a login (no public invoker below)

  template {
    scaling {
      min_instance_count = 0 # nothing runs (or costs) when idle
      max_instance_count = 1 # hard limit on how much can run at once
    }
    max_instance_request_concurrency = 4
    timeout                          = "60s"
    service_account                  = google_service_account.runtime.email # no permissions (github.tf)

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/scam-detector/app:${var.image_tag}"
      ports {
        container_port = 8080
      }
      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi" # AlephBERT + PyTorch need ~1.2 GB
        }
        cpu_idle          = true # CPU only while handling a request (cheapest billing)
        startup_cpu_boost = true # faster model loading on cold start
      }
    }
  }

  lifecycle {
    # deploy\deploy.ps1 rolls out new images; Terraform owns everything else
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [google_project_service.apis]
}

# Deliberately NO google_cloud_run_v2_service_iam_member for "allUsers":
# the service stays private until rate limiting is in place and the IP clause is checked.

output "service_url" {
  value = google_cloud_run_v2_service.app.uri
}
