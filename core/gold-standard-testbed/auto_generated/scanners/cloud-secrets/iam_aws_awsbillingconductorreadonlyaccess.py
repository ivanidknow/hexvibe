# Vulnerable: IAM-AWS-AWSBillingConductorReadOnlyAccess
{
  "Action": [
    "billingconductor:List*",
    "billingconductor:GetBillingGroupCostReport",
    "organizations:ListAccounts",
    "pricing:DescribeServices",
    "pricing:GetAttributeValues",
    "pricing:GetProducts",
...
  "Resource": "*"
}
