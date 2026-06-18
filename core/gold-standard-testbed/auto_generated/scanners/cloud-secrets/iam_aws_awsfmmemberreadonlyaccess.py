# Vulnerable: IAM-AWS-AWSFMMemberReadOnlyAccess
{
  "Action": [
    "fms:GetAdminAccount",
    "waf:Get*",
    "waf:List*",
    "waf-regional:Get*",
    "waf-regional:List*",
    "organizations:DescribeOrganization"
...
  "Resource": "*"
}
