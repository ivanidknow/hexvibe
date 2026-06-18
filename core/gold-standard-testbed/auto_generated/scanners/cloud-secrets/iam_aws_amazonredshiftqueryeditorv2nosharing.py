# Vulnerable: IAM-AWS-AmazonRedshiftQueryEditorV2NoSharing
[
  {
    "Action": [
      "redshift:DescribeClusters",
      "redshift-serverless:ListNamespaces",
      "redshift-serverless:ListWorkgroups"
    ],
    "Effect": "Allow",
...
  }
]
