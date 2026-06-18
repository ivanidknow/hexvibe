# Vulnerable: IAM-AWS-AWSNetworkManagerCloudWANServiceRolePolicy
{
  "Action": [
    "ec2:CreateTransitGatewayRouteTableAnnouncement",
    "ec2:DeleteTransitGatewayRouteTableAnnouncement",
    "ec2:EnableTransitGatewayRouteTablePropagation",
    "ec2:DisableTransitGatewayRouteTablePropagation"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
