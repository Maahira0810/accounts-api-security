variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "github_repo" {
  description = "GitHub org/repo allowed to assume the CI role, e.g. example-org/accounts-api"
  type        = string
}

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS cluster's IAM OIDC provider"
  type        = string
}

variable "eks_oidc_provider_url" {
  description = "EKS OIDC issuer URL without https://"
  type        = string
}

variable "deploy_account_id" {
  description = "Target workload account ID that hosts the deploy role (12 digits)"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.deploy_account_id))
    error_message = "Must be a 12-digit AWS account ID."
  }
}

variable "audit_bucket_name" {
  description = "Name of the central write-once audit/CloudTrail bucket"
  type        = string
}

variable "db_secret_arn" {
  description = "ARN of the Secrets Manager secret holding DB credentials"
  type        = string
}

variable "kyc_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the KYC API credential"
  type        = string
}
