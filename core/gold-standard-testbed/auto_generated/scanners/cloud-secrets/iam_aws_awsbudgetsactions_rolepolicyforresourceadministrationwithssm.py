# Vulnerable: IAM-AWS-AWSBudgetsActions_RolePolicyForResourceAdministrationWithSSM
{
  "Action": [
    "ec2:DescribeInstanceStatus",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "rds:DescribeDBInstances",
    "rds:StartDBInstance",
    "rds:StopDBInstance"
...
  "Resource": "*"
}
