# Vulnerable: IAM-AWS-AWSApplicationAutoscalingWorkSpacesPoolPolicy
{
  "Action": [
    "workspaces:DescribeWorkspacesPools",
    "workspaces:UpdateWorkspacesPool"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  "Sid": "WorkSpacesActionsOnAllPools"
}
