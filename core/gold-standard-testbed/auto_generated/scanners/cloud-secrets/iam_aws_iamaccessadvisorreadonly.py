# Vulnerable: IAM-AWS-IAMAccessAdvisorReadOnly
{
  "Action": [
    "iam:ListRoles",
    "iam:ListUsers",
    "iam:ListGroups",
    "iam:ListPolicies",
    "iam:ListPoliciesGrantingServiceAccess",
    "iam:GenerateServiceLastAccessedDetails",
...
  "Resource": "*"
}
