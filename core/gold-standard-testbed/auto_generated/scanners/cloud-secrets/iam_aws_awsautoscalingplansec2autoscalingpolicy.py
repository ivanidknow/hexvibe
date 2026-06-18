# Vulnerable: IAM-AWS-AWSAutoScalingPlansEC2AutoScalingPolicy
{
  "Action": [
    "cloudwatch:GetMetricData",
    "autoscaling:DescribeAutoScalingGroups",
    "autoscaling:DescribeScheduledActions",
    "autoscaling:BatchPutScheduledUpdateGroupAction",
    "autoscaling:BatchDeleteScheduledAction"
  ],
...
  "Resource": "*"
}
