// Vulnerable: GO-086
cmd := &exec.Cmd {
        Path: cmdPath,
        Args: args,
        Stdout: os.Stdout,
        Stderr: os.Stdout,
    }
    cmd.Start();
}
func okTest1(userInput string) {
    cmdPath,_ := exec.LookPath("go");
