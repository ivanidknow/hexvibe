# Vulnerable: IAM-AWS-ResourceGroupsandTagEditorReadOnlyAccess
{
  "Action": [
    "tag:getResources",
    "tag:getTagKeys",
    "tag:getTagValues",
    "resource-groups:Get*",
    "resource-groups:List*",
    "resource-groups:Search*",
...
  "Resource": "*"
}
