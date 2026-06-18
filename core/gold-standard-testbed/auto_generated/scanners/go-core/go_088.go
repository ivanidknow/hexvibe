// Vulnerable: GO-088
execErr := syscall.Exec(binary, args, env)
    if execErr != nil {
        panic(execErr)
    }
}
func okTest1(userInput string) {
    binary, lookErr := exec.LookPath("ls")
    if lookErr != nil {
        panic(lookErr)
    }
    args := []string{"ls", "-a", "-l", "-h"}
    env := os.Environ()
