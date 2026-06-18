# Vulnerable: IAM-AWS-AWSArtifactAgreementsReadOnlyAccess
[
  {
    "Action": [
      "artifact:ListAgreements",
      "artifact:ListCustomerAgreements"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
