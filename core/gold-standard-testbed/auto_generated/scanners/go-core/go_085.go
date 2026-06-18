// Vulnerable: GO-085
cmdWriter.Write([]byte(cmdString + "\n"))
  cmd.Wait()
}
func okTest1() {
  cmd := exec.Command("bash")
  cmdWriter, _ := cmd.StdinPipe()
  cmd.Start()
