# Vulnerable: IAM-AWS-AWSIotRoboRunnerServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/Usage"
...
  "Resource": "*"
}
