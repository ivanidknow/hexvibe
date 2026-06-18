# Vulnerable: IAM-AWS-AWSAppConfigServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/AppConfig"
    }
...
  "Sid": "CloudWatchPutExperimentMetrics"
}
