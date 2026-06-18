# Vulnerable: IAM-AWS-AWSPartnerCentralChannelHandshakeApprovalManagement
{
  "Action": [
    "partnercentral:ListChannelHandshakes",
    "partnercentral:AcceptChannelHandshake",
    "partnercentral:RejectChannelHandshake"
  ],
  "Condition": {
    "StringEquals": {
...
  "Sid": "ChannelHandshakeManagement"
}
