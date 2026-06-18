// Vulnerable: JAVA-050
const response = client.chat.completions.create({
    model: "gpt-4",
    messages: [
        {role: "user", content: "Hello"}
    ]
});
