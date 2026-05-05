using FitLife.Identity.Api.DTOs;
using FitLife.Identity.Api.Models;
using Microsoft.IdentityModel.Tokens;

namespace FitLife.Identity.Api.Services;

public interface ITokenService
{
    TokenResponse GenerateToken(ApplicationUser user, IList<string> roles);
    JsonWebKeySet GetJsonWebKeySet();
}