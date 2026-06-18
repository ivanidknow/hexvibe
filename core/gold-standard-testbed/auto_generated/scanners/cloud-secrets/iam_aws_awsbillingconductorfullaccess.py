# Vulnerable: IAM-AWS-AWSBillingConductorFullAccess
{
  "Action": [
    "billingconductor:*",
    "organizations:ListAccounts",
    "pricing:DescribeServices",
    "pricing:GetAttributeValues",
    "pricing:GetProducts",
    "organizations:ListRoots",
...
  "Resource": "*"
}
