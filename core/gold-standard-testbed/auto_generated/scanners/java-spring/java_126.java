// Vulnerable: JAVA-126
const data = await ddbDocClient.send(new QueryCommand(params));
  console.log("Success:", data.Items);
}
exports.handler = function(event, context) {
  const ddbClient = new DynamoDBClient({ region: 'REGION' });
  const ddbDocClient = DynamoDBDocumentClient.from(ddbClient);
  const params = {
    KeyConditionExpression: "Title = :s",
    ExpressionAttributeValues: {
      ":s": { S: event.body.title }
...
    TableName: "TVSHOWS",
  }
