# Vulnerable: IAM-AWS-AmazonElasticMapReduceforAutoScalingRole
{
  "Action": [
    "cloudwatch:DescribeAlarms",
    "elasticmapreduce:ListInstanceGroups",
    "elasticmapreduce:ModifyInstanceGroups"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
