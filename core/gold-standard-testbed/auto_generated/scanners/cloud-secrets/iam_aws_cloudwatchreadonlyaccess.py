# Vulnerable: IAM-AWS-CloudWatchReadOnlyAccess
{
  "Action": [
    "application-autoscaling:DescribeScalingPolicies",
    "application-signals:BatchGet*",
    "application-signals:Get*",
    "application-signals:List*",
    "autoscaling:Describe*",
    "cloudtrail:ListChannels",
...
  "Sid": "CloudWatchReadOnlyAccessPermissions"
}
