# Vulnerable: IAM-AWS-AmazonSageMakerCanvasSMDataScienceAssistantAccess
[
  {
    "Action": [
      "sagemaker-data-science-assistant:SendConversation"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
