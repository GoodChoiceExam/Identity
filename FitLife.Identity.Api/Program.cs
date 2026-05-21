using System.Text;
using AspNetCore.Identity.MongoDbCore.Models;
using FitLife.Identity.Api.Models;
using FitLife.Identity.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
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

    var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "fitlife-identity";
    var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "fitlife";
    var secret = builder.Configuration["Jwt:Secret"] ?? throw new InvalidOperationException("Jwt:Secret is not configured");

    builder.Services
        .AddAuthentication()
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtIssuer,
                ValidateAudience = true,
                ValidAudience = jwtAudience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    logger.Warn(context.Exception, "JWT authentication failed");
                    return Task.CompletedTask;
                },
                OnChallenge = context =>
                {
                    logger.Warn("Unauthorized request to {Path}", context.Request.Path);
                    return Task.CompletedTask;
                }
            };
        });

    builder.Services.AddAuthorization();
    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddHostedService<HeartbeatService>();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(options =>
    {
        options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Enter a valid JWT Bearer token from the Identity service."
        });

        options.AddSecurityRequirement(_ => new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecuritySchemeReference("Bearer", null, null),
                []
            }
        });
    });
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Frontend", policy =>
            policy.WithOrigins(
                    "http://localhost:5271",
                    "http://localhost",
                    "https://goodchoice.cc")
                .AllowAnyHeader()
                .AllowAnyMethod());
    });

    var app = builder.Build();
    logger.Info("FitLife Identity API starting");

    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("Frontend");
    app.UseAuthentication();
    app.UseAuthorization();
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
