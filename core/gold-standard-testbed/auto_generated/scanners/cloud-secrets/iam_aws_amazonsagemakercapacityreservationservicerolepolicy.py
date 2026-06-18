# Vulnerable: IAM-AWS-AmazonSageMakerCapacityReservationServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "aws/sagemaker/CapacityReservations"
    }
...
  "Sid": "CloudwatchPutMetricDataAccess"
}
