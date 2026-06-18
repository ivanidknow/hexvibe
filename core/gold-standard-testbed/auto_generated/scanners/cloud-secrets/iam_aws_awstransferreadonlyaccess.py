# Vulnerable: IAM-AWS-AWSTransferReadOnlyAccess
{
  "Action": [
    "transfer:DescribeUser",
    "transfer:DescribeServer",
    "transfer:ListUsers",
    "transfer:ListServers",
    "transfer:TestIdentityProvider",
    "transfer:ListTagsForResource"
...
  "Resource": "*"
}
