output "intake_url" {
  value       = google_cloud_run_v2_service.intake.uri
  description = "Point the Wiz automation rule at ${"$"}{intake_url}/webhook/wiz."
}

output "worker_url" {
  value       = google_cloud_run_v2_service.worker.uri
  description = "Internal only; Cloud Tasks invokes this with an OIDC token."
}

output "service_accounts" {
  value = {
    intake        = google_service_account.intake.email
    worker        = google_service_account.worker.email
    tasks_invoker = google_service_account.tasks_invoker.email
  }
  description = "Grant the worker's identity access to any additional resources it needs."
}
