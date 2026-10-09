provider "google" {
  project = var.google_project
  region  = var.google_region
}

# Source : deploy.sh:8 (confiance 100%)
# Origine : gcloud compute instances create web --zone europe-west1-b --machine-type e2-small --image-family debian-12 --image-proje
resource "google_compute_instance" "web" {
  name         = "web"
  machine_type = "e2-small"
  zone         = "europe-west1-b"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
    access_config {
    }
  }
}

# Source : deploy.sh:9 (confiance 100%)
# Origine : gcloud compute firewall-rules create allow-web --network default --allow tcp:22,tcp:80 --source-ranges 10.0.0.0/8
resource "google_compute_firewall" "allow_web" {
  name          = "allow-web"
  network       = "default"
  source_ranges = ["10.0.0.0/8"]
  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }
}
