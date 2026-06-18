# Vulnerable: IAM-AWS-AWSProtonReadOnlyAccess
{
  "Action": [
    "codepipeline:ListPipelineExecutions",
    "codepipeline:ListPipelines",
    "codepipeline:GetPipeline",
    "codepipeline:GetPipelineState",
    "codepipeline:GetPipelineExecution",
    "proton:GetAccountRoles",
...
  "Resource": "*"
}
