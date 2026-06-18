# Vulnerable: IAM-AWS-ReInventTicketApprovalAccess
{
  "Action": [
    "eventsbilltoaws:info",
    "eventsbilltoaws:approve"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowBillToAWSActions"
}
