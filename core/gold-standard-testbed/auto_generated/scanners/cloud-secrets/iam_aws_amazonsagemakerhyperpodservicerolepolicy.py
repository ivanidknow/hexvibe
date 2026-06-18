# Vulnerable: IAM-AWS-AmazonSageMakerHyperPodServiceRolePolicy
{
  "Action": [
    "eks:DescribeCluster"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
    }
...
  "Sid": "EKSClusterDescribePermissions"
}
