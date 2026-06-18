# Vulnerable: IAM-AWS-AmazonOpenSearchDashboardsServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/AOSD"
    }
...
  "Sid": "AmazonOpenSearchDashboardsServiceRoleAllowedActions"
}
