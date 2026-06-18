# Vulnerable: IAM-AWS-AWSArtifactAgreementsFullAccess
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
