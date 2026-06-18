# Vulnerable: IAM-AWS-AWSApplicationMigrationConversionServerPolicy
{
  "Action": [
    "mgn:SendClientMetricsForMgn",
    "mgn:SendClientLogsForMgn",
    "mgn:GetChannelCommandsForMgn",
    "mgn:SendChannelCommandResultForMgn"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
