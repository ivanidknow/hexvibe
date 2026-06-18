# Vulnerable: IAM-AWS-AWSXrayReadOnlyAccess
{
  "Action": [
    "xray:GetSamplingRules",
    "xray:GetSamplingTargets",
    "xray:GetSamplingStatisticSummaries",
    "xray:BatchGetTraces",
    "xray:BatchGetTraceSummaryById",
    "xray:GetDistinctTraceGraphs",
...
  "Sid": "AWSXrayReadOnlyAccess"
}
