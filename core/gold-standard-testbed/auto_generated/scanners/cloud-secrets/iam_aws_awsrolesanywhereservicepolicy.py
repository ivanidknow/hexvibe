# Vulnerable: IAM-AWS-AWSRolesAnywhereServicePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/RolesAnywhere",
...
  "Resource": "*"
}
