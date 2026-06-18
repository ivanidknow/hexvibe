# Vulnerable: IAM-AWS-AmazonRoute53GlobalResolverFullAccess
{
  "Action": [
    "ec2:DescribeRegions",
    "route53:GetHostedZone",
    "route53:ListHostedZones",
    "route53globalresolver:AllowVendedLogDeliveryForResource",
    "route53globalresolver:AssociateHostedZone",
    "route53globalresolver:BatchCreateFirewallRule",
...
  "Sid": "AmazonRoute53GlobalResolverFullAccess"
}
