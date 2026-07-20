terraform {
  required_version = ">= 1.9"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  services = ["run.googleapis.com", "cloudtasks.googleapis.com", "cloudbuild.googleapis.com",
  "firestore.googleapis.com", "secretmanager.googleapis.com", "artifactregistry.googleapis.com"]
}

resource "google_project_service" "enabled" {
  for_each                   = toset(local.services)
  service                    = each.value
  disable_dependent_services = false
  disable_on_destroy         = false
}

# --- Identities ---------------------------------------------------------------------------------
# Three separate service accounts so a compromise of intake cannot reach the GitHub App key, and
# neither can mint tokens for the other.

resource "google_service_account" "intake" {
  account_id   = "sfb-intake"
  display_name = "Sir-Fix-A-Bot intake"
  description  = "Receives Wiz webhooks, deduplicates and enqueues"
}

resource "google_service_account" "worker" {
  account_id   = "sfb-worker"
  display_name = "Sir-Fix-A-Bot worker"
  description  = "Runs the remediation agent and opens pull requests"
}

resource "google_service_account" "tasks_invoker" {
  account_id   = "sfb-tasks-invoker"
  display_name = "Sir-Fix-A-Bot Cloud Tasks invoker"
  description  = "Identity Cloud Tasks mints OIDC tokens as when calling the worker"
}

# --- Secrets ------------------------------------------------------------------------------------
# Values are set out of band. Terraform creates the containers and the access bindings only, so no
# secret material passes through state.

resource "google_secret_manager_secret" "secrets" {
  for_each  = toset(var.secret_names)
  secret_id = each.value
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "worker_access" {
  for_each  = google_secret_manager_secret.secrets
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

# Intake needs only the webhook secret — not the GitHub key, not the Anthropic key.
resource "google_secret_manager_secret_iam_member" "intake_access" {
  secret_id = google_secret_manager_secret.secrets["sfb-wiz-webhook-secret"].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.intake.email}"
}

# --- Firestore ----------------------------------------------------------------------------------

resource "google_firestore_database" "runs" {
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
  depends_on  = [google_project_service.enabled]
}

resource "google_project_iam_member" "intake_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.intake.email}"
}

resource "google_project_iam_member" "worker_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

# The worker submits verification builds; Cloud Run cannot host a privileged Docker daemon.
resource "google_project_iam_member" "worker_cloudbuild" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.editor"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_project_iam_member" "worker_storage" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

# --- Cloud Tasks --------------------------------------------------------------------------------

resource "google_cloud_tasks_queue" "remediation" {
  name     = "sir-fix-a-bot"
  location = var.region

  rate_limits {
    # The worker runs one finding per instance, so queue concurrency is the real throttle. This
    # also bounds Anthropic spend and Cloud Build usage during a large rescan.
    max_concurrent_dispatches = var.max_concurrent_remediations
    max_dispatches_per_second = 1
  }

  retry_config {
    max_attempts = 3
    # A failed run is usually a bad fix rather than a transient error, so back off hard.
    min_backoff = "60s"
    max_backoff = "600s"
  }

  depends_on = [google_project_service.enabled]
}

resource "google_project_iam_member" "intake_enqueue" {
  project = var.project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.intake.email}"
}

# Intake must be able to mint OIDC tokens as the invoker identity.
resource "google_service_account_iam_member" "intake_acts_as_invoker" {
  service_account_id = google_service_account.tasks_invoker.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.intake.email}"
}

# --- Cloud Run ----------------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "worker" {
  name                = "sfb-worker"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = false

  template {
    service_account = google_service_account.worker.email
    # gen1's gVisor sandbox breaks git and the Node MCP subprocess.
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    # The real ceiling is the Cloud Tasks 30-minute dispatch deadline, not Cloud Run's 60-minute
    # request timeout: past it Tasks abandons the request and retries while the worker is still
    # running, which produces duplicate pull requests.
    timeout                          = "1800s"
    max_instance_request_concurrency = 1

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_worker_instances
    }

    containers {
      image = var.worker_image

      resources {
        limits = {
          # Cloud Run's filesystem is tmpfs and counts against this limit, so the cloned repo
          # lives in the memory budget. Clones are shallow and blobless for the same reason.
          memory = "4Gi"
          cpu    = "2"
        }
        # Keep the CPU allocated for the whole request; the agent spends long periods awaiting
        # the model API and must not be throttled mid-run.
        cpu_idle          = false
        startup_cpu_boost = true
      }

      dynamic "env" {
        for_each = var.worker_env
        content {
          name  = env.key
          value = env.value
        }
      }

      startup_probe {
        http_get { path = "/healthz" }
        initial_delay_seconds = 5
        timeout_seconds       = 5
        failure_threshold     = 10
      }
    }
  }
}

resource "google_cloud_run_v2_service" "intake" {
  name                = "sfb-intake"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL" # Wiz calls this from the internet.
  deletion_protection = false

  template {
    service_account       = google_service_account.intake.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    timeout               = "30s"

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = var.intake_image

      resources {
        limits = {
          memory = "512Mi"
          cpu    = "1"
        }
      }

      dynamic "env" {
        for_each = merge(var.intake_env, {
          SFB_WORKER_URL       = google_cloud_run_v2_service.worker.uri
          SFB_TASKS_INVOKER_SA = google_service_account.tasks_invoker.email
        })
        content {
          name  = env.key
          value = env.value
        }
      }

      startup_probe {
        http_get { path = "/healthz" }
      }
    }
  }
}

# Only Cloud Tasks may invoke the worker. There is no public invoker binding — that is what stops
# anyone POSTing a fabricated finding straight to the remediation endpoint.
resource "google_cloud_run_v2_service_iam_member" "tasks_invokes_worker" {
  name     = google_cloud_run_v2_service.worker.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.tasks_invoker.email}"
}

# Intake is public at the transport layer; the shared secret in the request header is what
# authenticates Wiz. Consider fronting it with Cloud Armor if the endpoint gets probed.
resource "google_cloud_run_v2_service_iam_member" "public_intake" {
  name     = google_cloud_run_v2_service.intake.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
