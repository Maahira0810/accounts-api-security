terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Production: remote state in S3 with KMS + versioning + DynamoDB/S3 locking, in a dedicated state account (T10).
}

provider "aws" {
  region = var.region
}
