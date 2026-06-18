# Vulnerable: IAM-AWS-AWSServiceRoleForAWSTransformCustom
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/TransformCustom"
    }
...
  "Resource": "*"
}
