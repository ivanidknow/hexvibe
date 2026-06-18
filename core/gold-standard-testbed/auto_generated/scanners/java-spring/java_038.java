// Vulnerable: JAVA-038
const response = await model.generateContent({
    contents: [{ role: "user", parts: [{ text: "Hello" }] }]
});
