variable "aws_region" {
  type        = string
  description = "Région AWS des ressources importées"
}

variable "google_project" {
  type = string
}

variable "google_region" {
  type    = string
  default = "europe-west1"
}

variable "os_environ__ami" {
  description = "TODO : valeur issue du code source"
}
