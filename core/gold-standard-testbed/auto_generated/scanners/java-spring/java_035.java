// Vulnerable: JAVA-035
const response = await co.chat({
    model: "command-a-03-2025",
    messages: [{ role: "user", content: "Hello" }]
});
