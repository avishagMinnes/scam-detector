variable "project_id" {
  description = "Google Cloud project"
  type        = string
  default     = "scam-detector-511311"
}

variable "region" {
  description = "Region; us-central1 is inside Cloud Run's free tier"
  type        = string
  default     = "us-central1"
}

variable "alert_email" {
  description = "Where alert emails go. Set in infra/terraform.tfvars (kept out of Git)"
  type        = string
}

variable "image_tag" {
  description = "Image tag used when Terraform first creates the service (later images come from deploy.ps1)"
  type        = string
  default     = "latest"
}
