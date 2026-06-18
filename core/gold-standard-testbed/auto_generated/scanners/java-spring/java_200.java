// Vulnerable: JAVA-200
const gitClone = childProcess.spawn('git', [ 'clone', gitUrl ]);
        return res.send('ok');
    }
}
function testOk1() {
    const { spawn } = require('child_process');
    function downloadGitCommitOk1() {
