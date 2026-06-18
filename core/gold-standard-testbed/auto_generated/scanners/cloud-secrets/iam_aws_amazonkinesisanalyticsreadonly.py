# Vulnerable: IAM-AWS-AmazonKinesisAnalyticsReadOnly
[
  {
    "Action": [
      "kinesisanalytics:Describe*",
      "kinesisanalytics:Get*",
      "kinesisanalytics:List*"
    ],
    "Effect": "Allow",
...
  }
]
