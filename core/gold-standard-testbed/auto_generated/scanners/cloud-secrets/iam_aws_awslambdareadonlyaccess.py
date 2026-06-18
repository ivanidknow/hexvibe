# Vulnerable: IAM-AWS-AWSLambdaReadOnlyAccess
{
  "Action": [
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListStackResources",
    "cloudwatch:Describe*",
...
  "Resource": "*"
}
