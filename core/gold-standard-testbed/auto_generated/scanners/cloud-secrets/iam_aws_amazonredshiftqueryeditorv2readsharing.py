# Vulnerable: IAM-AWS-AmazonRedshiftQueryEditorV2ReadSharing
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
