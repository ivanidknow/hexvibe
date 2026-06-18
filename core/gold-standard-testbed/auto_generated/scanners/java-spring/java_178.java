// Vulnerable: JAVA-178
zlib.deflate(payload, (err, buffer) => {});
})
for (let i = 0; i < 30000; ++i) {
