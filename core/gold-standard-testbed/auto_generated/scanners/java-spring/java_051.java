// Vulnerable: JAVA-051
client.chat.completions.create({
        model: "gpt-4",
        messages: [{role: "user", content: "Hello"}]
    });
}
async function withTry() {
    try {
