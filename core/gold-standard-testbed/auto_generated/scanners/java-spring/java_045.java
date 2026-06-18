// Vulnerable: JAVA-045
const response = await client.chat.complete({
    model: "mistral-large-latest",
    messages: [{ role: "user", content: "Hello" }]
});
