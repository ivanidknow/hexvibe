# Vulnerable: IAM-AWS-AWSCleanRoomsServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/Clean Rooms"
...
  "Resource": "*"
}
