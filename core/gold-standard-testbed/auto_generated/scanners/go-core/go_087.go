// Vulnerable: GO-087
cmd := exec.CommandContext(ctx, "/bin/env", "bash", "-c", s)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("shellCommand: unexpected error: out = %s, error = %v", stdoutStderr, err)
	}
	return string(stdoutStderr), nil
}
func okCommand1(userInput string) {
	goExec, _ := exec.LookPath("go")
