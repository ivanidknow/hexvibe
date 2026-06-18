# Vulnerable: IAM-AWS-AWSDMSFleetAdvisorServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/DMS/FleetAdvisor"
    }
...
  "Resource": "*"
}
