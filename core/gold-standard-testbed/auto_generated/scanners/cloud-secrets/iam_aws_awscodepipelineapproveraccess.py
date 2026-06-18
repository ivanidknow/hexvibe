# Vulnerable: IAM-AWS-AWSCodePipelineApproverAccess
{
  "Action": [
    "codepipeline:GetPipeline",
    "codepipeline:GetPipelineState",
    "codepipeline:GetPipelineExecution",
    "codepipeline:ListPipelineExecutions",
    "codepipeline:ListPipelines",
    "codepipeline:PutApprovalResult"
...
  "Resource": "*"
}
