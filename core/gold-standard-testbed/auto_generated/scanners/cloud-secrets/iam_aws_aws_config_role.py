# Vulnerable: IAM-AWS-AWS_Config_Role
{
  "Action": [
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "acm:ListTagsForCertificate",
    "application-autoscaling:DescribeScalableTargets",
    "application-autoscaling:DescribeScalingPolicies",
    "autoscaling:DescribeAutoScalingGroups",
...
  "Resource": "*"
}
