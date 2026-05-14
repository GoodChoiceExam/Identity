using AspNetCore.Identity.MongoDbCore.Models;
using FitLife.Identity.Api.Models;
using FitLife.Identity.Api.Services;
using Microsoft.AspNetCore.Identity;
using NLog;
using NLog.Web;

var logger = LogManager.Setup().LoadConfigurationFromFile("NLog.config").GetCurrentClassLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var mongoConn = builder.Configuration["MongoDB:ConnectionString"]!;
    var mongoDb   = builder.Configuration["MongoDB:DatabaseName"]!;

    builder.Services
        .AddIdentity<ApplicationUser, MongoIdentityRole<Guid>>()
        .AddMongoDbStores<ApplicationUser, MongoIdentityRole<Guid>, Guid>(mongoConn, mongoDb);

    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddCors(options =>
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("Frontend", policy =>
                policy.WithOrigins(
                        "http://localhost:5271")
                    .AllowAnyHeader()
                    .AllowAnyMethod());
        }));

    var app = builder.Build();

    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("Frontend");

    app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));
    app.MapControllers();

    await SeedRoles(app);

    app.Run();
}
catch (Exception ex)
{
    logger.Fatal(ex, "Application failed to start");
    throw;
}
finally
{
    LogManager.Shutdown();
}

static async Task SeedRoles(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<MongoIdentityRole<Guid>>>();
    foreach (var role in new[] { "Member", "Trainer", "Admin" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new MongoIdentityRole<Guid>(role));
    }
}