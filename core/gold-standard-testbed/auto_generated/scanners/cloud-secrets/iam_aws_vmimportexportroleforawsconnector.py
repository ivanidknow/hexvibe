# Vulnerable: IAM-AWS-VMImportExportRoleForAWSConnector
{
  "Action": [
    "ec2:ModifySnapshotAttribute",
    "ec2:CopySnapshot",
    "ec2:RegisterImage",
    "ec2:Describe*"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
