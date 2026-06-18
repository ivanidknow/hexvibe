# Vulnerable: IAM-AWS-AWSIoTFleetwiseServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/IoTFleetWise",
...
  "Resource": "*"
}
