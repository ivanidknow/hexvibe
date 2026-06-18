# Vulnerable: IAM-AWS-AWSGroundStationAgentInstancePolicy
{
  "Action": [
    "groundstation:RegisterAgent",
    "groundstation:UpdateAgentStatus",
    "groundstation:GetAgentConfiguration",
    "groundstation:GetAgentTaskResponseUrl"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
