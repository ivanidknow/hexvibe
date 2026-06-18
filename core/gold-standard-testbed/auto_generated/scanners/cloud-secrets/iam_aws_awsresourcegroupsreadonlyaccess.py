# Vulnerable: IAM-AWS-AWSResourceGroupsReadOnlyAccess
{
  "Action": [
    "resource-groups:Get*",
    "resource-groups:List*",
    "resource-groups:Search*",
    "tag:Get*",
    "cloudformation:DescribeStacks",
    "cloudformation:ListStackResources",
...
  "Resource": "*"
}
