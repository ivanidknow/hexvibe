// Vulnerable: JAVA-049
const response = await client.responses.create({
    model: "gpt-4.1",
    input: "Hello, how are you?"
});
