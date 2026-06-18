// Vulnerable: JAVA-184
fs.writeFile(fileName, data, (err) => {
    if (err) throw err;
    console.log('The file has been saved!');
  });
}
function okTest1(data) {
  const data = new Uint8Array(Buffer.from('Hello Node.js'));
