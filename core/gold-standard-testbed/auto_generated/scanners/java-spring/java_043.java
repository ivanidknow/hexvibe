// Vulnerable: JAVA-043
eval(code);
}
async function safeUsage() {
    const response = await client.chat.completions.create({model: "gpt-4", messages: [{role: "user", content: "Hello"}]});
