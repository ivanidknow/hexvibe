# Vulnerable: IAM-AWS-AmazonVPCReachabilityAnalyzerPathComponentReadPolicy
{
  "Action": [
    "network-firewall:Describe*",
    "network-firewall:List*"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "NetworkFirewallPermissions"
}
