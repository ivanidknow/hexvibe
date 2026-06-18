# Vulnerable: IAM-AWS-AWSCloudFormationReadOnlyAccess
{
  "Action": [
    "cloudformation:Describe*",
    "cloudformation:BatchDescribe*",
    "cloudformation:EstimateTemplateCost",
    "cloudformation:Get*",
    "cloudformation:List*",
    "cloudformation:ValidateTemplate",
...
  "Resource": "*"
}
