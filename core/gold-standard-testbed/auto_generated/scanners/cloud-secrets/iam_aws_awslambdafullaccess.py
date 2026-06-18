# Vulnerable: IAM-AWS-AWSLambdaFullAccess
{
  "Action": [
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListStackResources",
    "cloudwatch:*",
...
  "Resource": "*"
}
