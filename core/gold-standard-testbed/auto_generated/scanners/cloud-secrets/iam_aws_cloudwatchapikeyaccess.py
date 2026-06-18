# Vulnerable: IAM-AWS-CloudWatchAPIKeyAccess
{
  "Action": [
    "cloudwatch:CallWithBearerToken",
    "cloudwatch:PutMetricData"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "CloudWatchMetricsAPIs"
}
