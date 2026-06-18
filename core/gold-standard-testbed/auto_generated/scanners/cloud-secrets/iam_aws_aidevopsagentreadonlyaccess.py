# Vulnerable: IAM-AWS-AIDevOpsAgentReadOnlyAccess
{
  "Action": [
    "aidevops:DescribePrivateConnection",
    "aidevops:DescribeServices",
    "aidevops:Get*",
    "aidevops:List*",
    "aidevops:SearchServiceAccessibleResource"
  ],
...
  "Sid": "AIDevOpsAgentReadOnlyAccess"
}
