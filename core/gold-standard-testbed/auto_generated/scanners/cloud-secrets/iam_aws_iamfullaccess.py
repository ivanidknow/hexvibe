# Vulnerable: IAM-AWS-IAMFullAccess
{
  "Action": [
    "iam:*",
    "organizations:DescribeAccount",
    "organizations:DescribeOrganization",
    "organizations:DescribeOrganizationalUnit",
    "organizations:DescribePolicy",
    "organizations:ListChildren",
...
  "Resource": "*"
}
