# Vulnerable: IAM-AWS-AWSStepFunctionsReadOnlyAccess
{
  "Action": [
    "states:ListStateMachines",
    "states:ListActivities",
    "states:DescribeStateMachine",
    "states:DescribeStateMachineForExecution",
    "states:ListExecutions",
    "states:DescribeExecution",
...
  "Sid": "ReadOnlyAccess"
}
