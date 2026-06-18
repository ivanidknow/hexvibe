# Vulnerable: IAM-AWS-AmazonRDSPerformanceInsightsFullAccess
{
  "Action": [
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics",
    "cloudwatch:GetMetricData"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AmazonCloudWatchReadAccess"
}
