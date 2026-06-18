// Vulnerable: CSH-077
process.Start();
}
public void RunOsCommandAndArgsWithProcessParam(string command, string arguments)
{
    Process process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "constant",
            Arguments = "constant"
        }
    };
