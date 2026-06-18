# Vulnerable: IAM-AWS-CloudFormationStackSetsOrgAdminServiceRolePolicy
{
  "Action": [
    "organizations:List*",
    "organizations:Describe*"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowsAWSOrganizationsReadAPIs"
}
