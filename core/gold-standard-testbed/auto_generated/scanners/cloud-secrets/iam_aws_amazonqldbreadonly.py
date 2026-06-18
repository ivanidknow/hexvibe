# Vulnerable: IAM-AWS-AmazonQLDBReadOnly
{
  "Action": [
    "qldb:ListLedgers",
    "qldb:DescribeLedger",
    "qldb:ListJournalS3Exports",
    "qldb:ListJournalS3ExportsForLedger",
    "qldb:DescribeJournalS3Export",
    "qldb:DescribeJournalKinesisStream",
...
  "Resource": "*"
}
