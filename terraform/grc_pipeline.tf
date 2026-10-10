resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  github_oidc_arn = aws_iam_openid_connect_provider.github.arn
}

######################################################################
# CI identity: GitHub Actions OIDC, no stored AWS keys
# HIPAA 164.312(a)(1) Access Control, 164.312(d) Authentication
######################################################################

locals {
  github_repo       = "SeraphimO120/cgep-app-starter"
  github_sub_prefix = "repo:SeraphimO120@324516250/cgep-app-starter@1404925327"
  state_bucket      = "acme-health-intake-tfstate-5434b2b8"
}
# ---------- Plan role: pull requests only ----------

resource "aws_iam_role" "gha_plan" {
  name = "${local.name_prefix}-gha-plan-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "${local.github_sub_prefix}:pull_request"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "gha_plan" {
  name = "plan-state-lock-and-evidence"
  role = aws_iam_role.gha_plan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StateLock"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:aws:s3:::${local.state_bucket}/capstone/terraform.tfstate.tflock"
      },
      {
        Sid      = "EvidenceUpload"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/runs/*"
      },
      {
        Sid      = "EvidenceKeyEncryptOnly"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey"]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# ---------- Apply role: main branch only ----------

resource "aws_iam_role" "gha_apply" {
  name = "${local.name_prefix}-gha-apply-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "${local.github_sub_prefix}:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "gha_apply_admin" {
  role       = aws_iam_role.gha_apply.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------- Outputs for GitHub repo variables ----------

output "gha_plan_role_arn" {
  value = aws_iam_role.gha_plan.arn
}

output "gha_apply_role_arn" {
  value = aws_iam_role.gha_apply.arn
}