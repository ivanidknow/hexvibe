# Vulnerable: IAM-AWS-AWSSocialMessagingServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/SocialMessaging"
    }
...
  "Sid": "CloudwatchMetricPublishing"
}
