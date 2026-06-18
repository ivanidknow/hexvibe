# Vulnerable: IAM-AWS-AmazonRoute53RecoveryControlConfigReadOnlyAccess
{
  "Action": [
    "route53-recovery-control-config:DescribeCluster",
    "route53-recovery-control-config:DescribeControlPanel",
    "route53-recovery-control-config:DescribeRoutingControl",
    "route53-recovery-control-config:DescribeRoutingControlByName",
    "route53-recovery-control-config:DescribeSafetyRule",
    "route53-recovery-control-config:GetResourcePolicy",
...
  "Resource": "*"
}
