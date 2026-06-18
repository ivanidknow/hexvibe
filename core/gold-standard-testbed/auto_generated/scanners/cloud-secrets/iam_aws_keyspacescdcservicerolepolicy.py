# Vulnerable: IAM-AWS-KeyspacesCDCServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/Cassandra"
    }
...
  "Sid": "KeyspacesPutMetricDataPermission"
}
