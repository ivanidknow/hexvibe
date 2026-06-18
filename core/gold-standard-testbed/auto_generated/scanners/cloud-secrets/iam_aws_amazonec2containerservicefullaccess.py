# Vulnerable: IAM-AWS-AmazonEC2ContainerServiceFullAccess
{
  "Action": [
    "autoscaling:Describe*",
    "autoscaling:UpdateAutoScalingGroup",
    "cloudformation:CreateStack",
    "cloudformation:DeleteStack",
    "cloudformation:DescribeStack*",
    "cloudformation:UpdateStack",
...
  "Resource": "*"
}
