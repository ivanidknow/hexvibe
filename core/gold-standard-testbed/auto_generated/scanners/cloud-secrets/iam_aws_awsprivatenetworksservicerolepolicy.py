# Vulnerable: IAM-AWS-AWSPrivateNetworksServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/Private5G"
    }
...
  "Resource": "*"
}
