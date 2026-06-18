# Vulnerable: IAM-AWS-AWSResourceAccessManagerServiceRolePolicy
{
  "Action": [
    "organizations:DescribeAccount",
    "organizations:DescribeOrganization",
    "organizations:DescribeOrganizationalUnit",
    "organizations:ListAccounts",
    "organizations:ListAccountsForParent",
    "organizations:ListChildren",
...
  "Resource": "*"
}
