using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using FitLife.Identity.Api.DTOs;
using FitLife.Identity.Api.Models;
using Microsoft.IdentityModel.Tokens;

namespace FitLife.Identity.Api.Services;

public class TokenService : ITokenService
{
    private readonly RsaSecurityKey _privateKey;
    private readonly RsaSecurityKey _publicKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _expiryMinutes;

    public TokenService(IConfiguration configuration)
    {
        var keyId = configuration["Jwt:KeyId"] ?? "fitlife-key-1";
        var pemKey = configuration["Jwt:RsaPrivateKey"];

        RSA rsa;
        if (!string.IsNullOrEmpty(pemKey))
        {
            rsa = RSA.Create();
            rsa.ImportFromPem(pemKey.Replace("\\n", "\n"));
        }
        else
        {
            rsa = RSA.Create(2048); // dev fallback — ny nøgle ved hver genstart
        }

        _privateKey = new RsaSecurityKey(rsa) { KeyId = keyId };

        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        _publicKey = new RsaSecurityKey(publicRsa) { KeyId = keyId };

        _issuer = configuration["Jwt:Issuer"] ?? "fitlife-identity";
        _audience = configuration["Jwt:Audience"] ?? "fitlife";
        _expiryMinutes = int.TryParse(configuration["Jwt:ExpiryMinutes"], out var m) ? m : 60;
    }

    public TokenResponse GenerateToken(ApplicationUser user, IList<string> roles)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Name, user.FullName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var expires = DateTime.UtcNow.AddMinutes(_expiryMinutes);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: expires,
            signingCredentials: new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256)
        );

        return new TokenResponse(new JwtSecurityTokenHandler().WriteToken(token), expires);
    }

    public JsonWebKeySet GetJsonWebKeySet()
    {
        var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(_publicKey);
        return new JsonWebKeySet { Keys = { key } };
    }
}