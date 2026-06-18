# Vulnerable: IAM-AWS-CloudWatchFullAccess
{
  "Action": [
    "autoscaling:Describe*",
    "cloudwatch:*",
    "logs:*",
    "sns:*",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
...
  "Resource": "*"
}
