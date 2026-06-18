# Vulnerable: IAM-AWS-SMSVoiceServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/SMSVoice"
    }
...
  "Resource": "*"
}
