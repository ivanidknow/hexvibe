# Vulnerable: IAM-AWS-AmazonDynamoDBReadOnlyAccess
{
  "Action": [
    "application-autoscaling:DescribeScalableTargets",
    "application-autoscaling:DescribeScalingActivities",
    "application-autoscaling:DescribeScalingPolicies",
    "cloudwatch:DescribeAlarmHistory",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DescribeAlarmsForMetric",
...
  "Sid": "GeneralReadOnlyAccess"
}
