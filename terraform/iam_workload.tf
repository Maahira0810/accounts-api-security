# Workload identity via IRSA + least-privilege policy. Addresses T02, T06, T07.
data "aws_iam_policy_document" "workload_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:sub"
      values   = ["system:serviceaccount:accounts:accounts-api"] # exactly one SA
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "workload" {
  name                 = "accounts-api-workload"
  assume_role_policy   = data.aws_iam_policy_document.workload_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "workload" {
  statement {
    sid       = "ReadOwnSecretsOnly"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.db_secret_arn, var.kyc_secret_arn] # no wildcard resources
  }
  statement {
    sid       = "DecryptViaSecretsManagerOnly"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
  # Event-stream consume permissions (e.g. sqs:ReceiveMessage / kinesis:GetRecords) go here, scoped to the single stream ARN.
}

resource "aws_iam_policy" "workload" {
  name   = "accounts-api-workload"
  policy = data.aws_iam_policy_document.workload.json
}

resource "aws_iam_role_policy_attachment" "workload" {
  role       = aws_iam_role.workload.name
  policy_arn = aws_iam_policy.workload.arn
}
