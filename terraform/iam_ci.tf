# GitHub Actions OIDC trust (no long-lived keys) and restricted cross-account deploy. Addresses T05, T06, T10.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # Thumbprint handling depends on provider version; AWS validates GitHub's root CA. Verify current guidance before apply.
}

data "aws_iam_policy_document" "ci_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only the protected 'production' environment on this exact repo. Not branches, forks, or PRs.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:production"]
    }
  }
}

resource "aws_iam_role" "ci_release" {
  name                 = "accounts-api-ci-release"
  assume_role_policy   = data.aws_iam_policy_document.ci_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "ci_release" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # this action does not support resource-level permissions
  }
  statement {
    sid = "PushToOneRepo"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage",
    ]
    resources = [aws_ecr_repository.accounts_api.arn]
  }
  statement {
    sid       = "AssumeDeployRoleInTargetAccounts"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::${var.deploy_account_id}:role/accounts-api-deploy"] # one role per environment account
  }
}

resource "aws_iam_role_policy" "ci_release" {
  name   = "ci-release"
  role   = aws_iam_role.ci_release.id
  policy = data.aws_iam_policy_document.ci_release.json
}

# Target-account side (apply in the workload account): who may assume the deploy role.
data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ci_release.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["accounts-api-release"] # confused-deputy guard; not a secret
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "accounts-api-deploy"
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  max_session_duration = 3600
}
# Deploy permissions (e.g. eks:DescribeCluster + EKS access entry bound to a namespaced K8s RBAC role) intentionally
# omitted here; grant only namespace "accounts" rights, never cluster-admin. Prefer a GitOps pull model (DECISIONS D06).
