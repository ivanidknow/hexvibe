# Vulnerable: IAM-AWS-EC2ImageBuilderLifecycleExecutionPolicy
{
  "Action": [
    "ec2:DescribeImages",
    "tag:GetResources",
    "imagebuilder:DeleteImage"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "ImageBuilderEC2TagServicePermission"
}
