# Vulnerable: IAM-AWS-AWSVPCFlowLogsServiceRolePolicy
{
  "Action": [
    "tag:GetResources",
    "autoscaling:DescribeTags"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowDescribeTagsOnAllEC2Resources"
}
