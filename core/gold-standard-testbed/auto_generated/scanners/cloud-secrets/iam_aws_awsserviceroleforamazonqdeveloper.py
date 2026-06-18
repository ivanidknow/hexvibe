# Vulnerable: IAM-AWS-AWSServiceRoleForAmazonQDeveloper
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/Q"
...
  "Sid": "sid1"
}
