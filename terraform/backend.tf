terraform {
  backend "s3" {
    bucket  = "acme-health-intake-tfstate-5434b2b8"
    key     = "capstone/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}