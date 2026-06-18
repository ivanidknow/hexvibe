# Vulnerable: IAM-AWS-ElementalActivationsGenerateLicenses
{
  "Action": [
    "elemental-activations:Get*",
    "elemental-activations:GenerateLicenses",
    "elemental-activations:StartFileUpload",
    "elemental-activations:CompleteFileUpload"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
