# Vulnerable: IAM-AWS-AWSQuickSightTimestreamPolicy
{
  "Action": [
    "timestream:Select",
    "timestream:CancelQuery",
    "timestream:ListTables",
    "timestream:ListDatabases",
    "timestream:ListMeasures",
    "timestream:DescribeTable",
...
  "Resource": "*"
}
