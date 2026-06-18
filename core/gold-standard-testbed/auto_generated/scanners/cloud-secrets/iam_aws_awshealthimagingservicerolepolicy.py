# Vulnerable: IAM-AWS-AWSHealthImagingServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/HealthImaging"
    }
...
  "Resource": "*"
}
