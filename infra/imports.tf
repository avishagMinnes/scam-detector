# These resources were first created by hand (2026-10-11). The import blocks let
# Terraform adopt them instead of creating duplicates. Safe to keep: once a resource
# is in the state, its import block does nothing.

import {
  for_each = toset(["run.googleapis.com", "artifactregistry.googleapis.com"])
  to       = google_project_service.apis[each.value]
  id       = "${var.project_id}/${each.value}"
}

import {
  to = google_artifact_registry_repository.images
  id = "projects/${var.project_id}/locations/${var.region}/repositories/scam-detector"
}

import {
  to = google_cloud_run_v2_service.app
  id = "projects/${var.project_id}/locations/${var.region}/services/scam-detector"
}
