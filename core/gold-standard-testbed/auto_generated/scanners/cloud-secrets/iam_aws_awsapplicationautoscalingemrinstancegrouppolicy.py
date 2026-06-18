# Vulnerable: IAM-AWS-AWSApplicationAutoscalingEMRInstanceGroupPolicy
{
  "Action": [
    "elasticmapreduce:ListInstanceGroups",
    "elasticmapreduce:ModifyInstanceGroups",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
  ],
...
  "Resource": "*"
}
