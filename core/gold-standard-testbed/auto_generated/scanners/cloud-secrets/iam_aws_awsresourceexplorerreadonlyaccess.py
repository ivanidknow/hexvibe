# Vulnerable: IAM-AWS-AWSResourceExplorerReadOnlyAccess
{
  "Action": [
    "resource-explorer-2:Get*",
    "resource-explorer-2:List*",
    "resource-explorer-2:Search",
    "resource-explorer-2:BatchGetView",
    "ec2:DescribeRegions",
    "ram:ListResources",
...
  "Sid": "ResourceExplorerReadOnlyAccess"
}
