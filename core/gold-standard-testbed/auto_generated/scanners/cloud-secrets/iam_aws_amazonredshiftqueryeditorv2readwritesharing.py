# Vulnerable: IAM-AWS-AmazonRedshiftQueryEditorV2ReadWriteSharing
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
