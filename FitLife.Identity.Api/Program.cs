using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
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

    var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "fitlife-identity";
    var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "fitlife";
    var jwksUrl = builder.Configuration["Jwt:JwksUrl"] ?? "http://localhost:5244/.well-known/jwks.json";

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
                IssuerSigningKeyResolver = (_, _, _, _) => JwksSigningKeyResolver.GetSigningKeys(jwksUrl)
            };
        });

    builder.Services.AddAuthorization();
    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Frontend", policy =>
            policy.WithOrigins("http://localhost:5271")
                .AllowAnyHeader()
                .AllowAnyMethod());
    });

    var app = builder.Build();

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

static class JwksSigningKeyResolver
{
    private static readonly HttpClient Client = new();
    private static DateTime _expiresAt = DateTime.MinValue;
    private static IReadOnlyCollection<SecurityKey> _cachedKeys = [];

    public static IEnumerable<SecurityKey> GetSigningKeys(string jwksUrl)
    {
        if (_cachedKeys.Count > 0 && DateTime.UtcNow < _expiresAt)
            return _cachedKeys;

        var json = Client.GetStringAsync(jwksUrl).GetAwaiter().GetResult();
        var jwks = new JsonWebKeySet(json);

        _cachedKeys = jwks.Keys.Cast<SecurityKey>().ToArray();
        _expiresAt = DateTime.UtcNow.AddMinutes(5);
        return _cachedKeys;
    }
}