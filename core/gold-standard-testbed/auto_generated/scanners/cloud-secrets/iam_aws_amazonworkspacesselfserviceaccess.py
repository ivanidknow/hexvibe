# Vulnerable: IAM-AWS-AmazonWorkSpacesSelfServiceAccess
{
  "Action": [
    "workspaces:RebootWorkspaces",
    "workspaces:RebuildWorkspaces",
    "workspaces:ModifyWorkspaceProperties"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
