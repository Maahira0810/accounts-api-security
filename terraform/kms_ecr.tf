# Customer-managed KMS keys and an immutable, scanned ECR repository. Addresses T01, T04, T07.
resource "aws_kms_key" "secrets" {
  description         = "accounts-api secrets and data encryption"
  enable_key_rotation = true
}

resource "aws_kms_key" "ecr" {
  description         = "accounts-api ECR encryption"
  enable_key_rotation = true
}

resource "aws_ecr_repository" "accounts_api" {
  name                 = "accounts-api"
  image_tag_mutability = "IMMUTABLE" # tags cannot be re-pointed; deploy by digest (T04)

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}
