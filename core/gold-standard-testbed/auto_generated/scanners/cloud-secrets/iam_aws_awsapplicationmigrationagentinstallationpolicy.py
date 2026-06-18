# Vulnerable: IAM-AWS-AWSApplicationMigrationAgentInstallationPolicy
{
  "Action": [
    "mgn:GetAgentInstallationAssetsForMgn",
    "mgn:SendClientMetricsForMgn",
    "mgn:SendClientLogsForMgn",
    "mgn:RegisterAgentForMgn",
    "mgn:VerifyClientRoleForMgn"
  ],
...
  "Resource": "*"
}
