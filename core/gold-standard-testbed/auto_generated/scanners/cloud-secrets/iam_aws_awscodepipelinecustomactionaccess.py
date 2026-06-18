# Vulnerable: IAM-AWS-AWSCodePipelineCustomActionAccess
{
  "Action": [
    "codepipeline:AcknowledgeJob",
    "codepipeline:GetJobDetails",
    "codepipeline:PollForJobs",
    "codepipeline:PutJobFailureResult",
    "codepipeline:PutJobSuccessResult"
  ],
...
  "Resource": "*"
}
