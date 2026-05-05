using System.IdentityModel.Tokens.Jwt;
using FitLife.Identity.Api.Models;
using FitLife.Identity.Api.Services;
using Microsoft.Extensions.Configuration;

namespace FitLife.Identity.Tests;

[TestFixture]
public class TokenServiceTests
{
    private TokenService _sut = null!;

    [SetUp]
    public void Setup()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"]        = "test-issuer",
                ["Jwt:Audience"]      = "test-audience",
                ["Jwt:ExpiryMinutes"] = "60",
                ["Jwt:KeyId"]         = "test-key-1",
                ["Jwt:RsaPrivateKey"] = ""
            })
            .Build();
        _sut = new TokenService(config);
    }

    [Test]
    public void GenerateToken_ReturnsNonEmptyAccessToken()
    {
        var user = new ApplicationUser { Email = "test@fitlife.dk", FullName = "Test Bruger" };

        var result = _sut.GenerateToken(user, ["Member"]);

        Assert.That(result.AccessToken, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public void GenerateToken_TokenUsesRS256()
    {
        var user = new ApplicationUser { Email = "test@fitlife.dk", FullName = "Test Bruger" };

        var result = _sut.GenerateToken(user, []);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.AccessToken);
        Assert.That(token.Header.Alg, Is.EqualTo("RS256"));
    }

    [Test]
    public void GenerateToken_TokenContainsCorrectEmailAndName()
    {
        var user = new ApplicationUser { Email = "test@fitlife.dk", FullName = "Test Bruger" };

        var result = _sut.GenerateToken(user, []);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.AccessToken);
        Assert.Multiple(() =>
        {
            Assert.That(token.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value,
                Is.EqualTo("test@fitlife.dk"));
            Assert.That(token.Claims.First(c => c.Type == JwtRegisteredClaimNames.Name).Value,
                Is.EqualTo("Test Bruger"));
        });
    }

    [Test]
    public void GenerateToken_ExpiryIsApproximatelyCorrect()
    {
        var user = new ApplicationUser { Email = "test@fitlife.dk", FullName = "Test Bruger" };

        var result = _sut.GenerateToken(user, []);

        Assert.That(result.ExpiresAt,
            Is.InRange(DateTime.UtcNow.AddMinutes(59), DateTime.UtcNow.AddMinutes(61)));
    }

    [Test]
    public void GetJsonWebKeySet_ReturnsOneKeyWithCorrectId()
    {
        var jwks = _sut.GetJsonWebKeySet();

        Assert.That(jwks.Keys, Has.Count.EqualTo(1));
        Assert.That(jwks.Keys[0].KeyId, Is.EqualTo("test-key-1"));
    }
}