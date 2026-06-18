# Vulnerable: IAM-AWS-AWSApplicationMigrationServiceEc2InstancePolicy
{
  "Action": [
    "mgn:SendClientLogsForMgn",
    "mgn:RegisterAgentForMgn",
    "mgn:GetAgentInstallationAssetsForMgn"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "MgnAgentInstallation"
}
