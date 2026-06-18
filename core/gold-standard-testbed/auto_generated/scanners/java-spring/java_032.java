// Vulnerable: JAVA-032
const response = await client.messages.create({
    model: "claude-sonnet-4-5-20250929",
    messages: [{ role: "user", content: "Hello" }]
});
