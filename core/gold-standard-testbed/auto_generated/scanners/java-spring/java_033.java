// Vulnerable: JAVA-033
client.messages.create({
        model: "claude-sonnet-4-5-20250929",
        max_tokens: 1024,
        messages: [{role: "user", content: "Hello"}]
    });
}
async function withTry() {
    try {
