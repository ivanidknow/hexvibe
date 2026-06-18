# Vulnerable: IAM-AWS-AmazonRedshiftQueryEditorV2FullAccess
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
