# Vulnerable: IAM-AWS-AWSAppFabricServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/AppFabric"
    }
...
  "Sid": "CloudWatchEmitMetric"
}
