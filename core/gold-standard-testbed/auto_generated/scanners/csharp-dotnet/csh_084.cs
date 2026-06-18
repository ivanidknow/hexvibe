// Vulnerable: CSH-084
app.UseDeveloperExceptionPage();
}
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
        if (env.EnvironmentName == "Development")
