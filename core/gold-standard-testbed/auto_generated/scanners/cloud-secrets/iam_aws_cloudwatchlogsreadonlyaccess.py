# Vulnerable: IAM-AWS-CloudWatchLogsReadOnlyAccess
{
  "Action": [
    "logs:Describe*",
    "logs:Get*",
    "logs:List*",
    "logs:StartQuery",
    "logs:StopQuery",
    "logs:TestMetricFilter",
...
  "Sid": "CloudWatchLogsReadOnlyAccess"
}
