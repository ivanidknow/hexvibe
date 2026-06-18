# Vulnerable: IAM-AWS-Route53RecoveryReadinessServiceRolePolicy
{
  "Action": [
    "apigateway:GET",
    "application-autoscaling:DescribeScalableTargets",
    "application-autoscaling:DescribeScalingPolicies",
    "autoscaling:DescribeAccountLimits",
    "autoscaling:DescribeAutoScalingGroups",
    "autoscaling:DescribeAutoScalingInstances",
...
  "Resource": "*"
}
