# Vulnerable: IAM-AWS-QAppsServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/QApps"
    }
...
  "Sid": "QAppsPutMetricDataPermission"
}
