# Vulnerable: IAM-AWS-AWSXRayDaemonWriteAccess
{
  "Action": [
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
    "xray:GetSamplingRules",
    "xray:GetSamplingTargets",
    "xray:GetSamplingStatisticSummaries"
  ],
...
  "Sid": "AWSXRayDaemonWriteAccess"
}
