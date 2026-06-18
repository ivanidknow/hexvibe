// Vulnerable: CSH-063
app.UseDirectoryBrowser(new DirectoryBrowserOptions
    {
        FileProvider = fileProvider,
        RequestPath = requestPath
    });
}
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    var builder = WebApplication.CreateBuilder(args);
