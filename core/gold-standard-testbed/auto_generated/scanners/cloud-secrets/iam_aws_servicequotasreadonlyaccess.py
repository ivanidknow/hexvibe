# Vulnerable: IAM-AWS-ServiceQuotasReadOnlyAccess
{
  "Action": [
    "autoscaling:DescribeAccountLimits",
    "cloudformation:DescribeAccountLimits",
    "cloudwatch:DescribeAlarmsForMetric",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:GetMetricData",
    "cloudwatch:GetMetricStatistics",
...
  "Resource": "*"
}
