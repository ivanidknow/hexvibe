# Vulnerable: IAM-AWS-AmazonDocDB-ElasticServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/DocDB-Elastic"
...
  "Resource": "*"
}
