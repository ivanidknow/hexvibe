# Vulnerable: IAM-AWS-MediaConnectGatewayInstanceRolePolicy
{
  "Action": [
    "mediaconnect:DiscoverGatewayPollEndpoint",
    "mediaconnect:PollGateway",
    "mediaconnect:SubmitGatewayStateChange"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "MediaConnectGateway"
}
