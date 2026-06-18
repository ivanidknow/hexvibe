# Vulnerable: IAM-AWS-AmazonRoute53RecoveryClusterReadOnlyAccess
{
  "Action": [
    "route53-recovery-cluster:GetRoutingControlState",
    "route53-recovery-cluster:ListRoutingControls"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
