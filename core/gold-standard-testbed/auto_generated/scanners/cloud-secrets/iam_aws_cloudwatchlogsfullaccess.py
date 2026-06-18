# Vulnerable: IAM-AWS-CloudWatchLogsFullAccess
{
  "Action": [
    "logs:*",
    "cloudwatch:GenerateQuery",
    "cloudwatch:GenerateQueryResultsSummary",
    "observabilityadmin:GetS3TableIntegration",
    "observabilityadmin:ListS3TableIntegrations",
    "observabilityadmin:ListTelemetryPipelines"
...
  "Sid": "CloudWatchLogsFullAccess"
}
