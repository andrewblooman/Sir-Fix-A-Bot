variable "project_id" {
  type        = string
  description = "GCP project hosting Sir-Fix-A-Bot."
}

variable "region" {
  type        = string
  default     = "europe-west2"
  description = "Region for Cloud Run, Cloud Tasks and Firestore."
}

variable "intake_image" {
  type        = string
  description = "Fully-qualified image for the intake service."
}

variable "worker_image" {
  type        = string
  description = "Fully-qualified image for the worker service."
}

variable "secret_names" {
  type = list(string)
  default = [
    "sfb-wiz-client-id",
    "sfb-wiz-client-secret",
    "sfb-wiz-webhook-secret",
    "sfb-notion-token",
    "sfb-github-app-private-key",
    "sfb-anthropic-api-key",
  ]
  description = <<-EOT
    Secret Manager secrets to create. Values are set out of band (`gcloud secrets versions add`)
    so no secret material passes through Terraform state.
  EOT
}

variable "max_concurrent_remediations" {
  type        = number
  default     = 3
  description = <<-EOT
    Queue-level concurrency cap. This is the main throttle on Anthropic spend and Cloud Build
    usage during a large Wiz rescan, when hundreds of findings can arrive at once.
  EOT
}

variable "max_worker_instances" {
  type        = number
  default     = 10
  description = "Upper bound on worker instances; the blast-radius and spend ceiling."
}

variable "intake_env" {
  type        = map(string)
  description = "Environment for the intake service. Secrets are Secret Manager resource names."
}

variable "worker_env" {
  type        = map(string)
  description = "Environment for the worker service. Secrets are Secret Manager resource names."
}
