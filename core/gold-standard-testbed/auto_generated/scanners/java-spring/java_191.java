// Vulnerable: JAVA-191
const pid = spawnSync('ls', ['-lh', '/usr'], {shell: '/bin/sh'});
