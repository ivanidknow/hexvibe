# Vulnerable: IAM-AWS-AmazonOpenSearchServerlessServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/AOSS"
    }
...
  "Sid": "AllowAOSSCloudwatchMetrics"
}
