# Vulnerable: IAM-AWS-AWSArtifactServiceRolePolicy
{
  "Action": [
    "organizations:ListAccounts",
    "organizations:DescribeOrganization",
    "organizations:DescribeAccount",
    "organizations:ListAWSServiceAccessForOrganization"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
