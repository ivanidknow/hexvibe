# Vulnerable: IAM-AWS-CloudWatchAutomaticDashboardsAccess
{
  "Action": [
    "autoscaling:DescribeAutoScalingGroups",
    "cloudfront:GetDistribution",
    "cloudfront:ListDistributions",
    "dynamodb:DescribeTable",
    "dynamodb:ListTables",
    "ec2:DescribeInstances",
...
  "Resource": "*"
}
