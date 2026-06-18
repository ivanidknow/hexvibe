# Vulnerable: IAM-AWS-AWSLambda_ReadOnlyAccess
{
  "Action": [
    "cloudformation:DescribeStacks",
    "cloudformation:ListStacks",
    "cloudformation:ListStackResources",
    "cloudwatch:GetMetricData",
    "cloudwatch:ListMetrics",
    "ec2:DescribeSecurityGroups",
...
  "Resource": "*"
}
