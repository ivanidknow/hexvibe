# Vulnerable: IAM-AWS-VPCLatticeReadOnlyAccess
{
  "Action": [
    "vpc-lattice:Get*",
    "vpc-lattice:List*",
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "cloudwatch:GetMetricData",
    "ec2:DescribeInstances",
...
  "Resource": "*"
}
