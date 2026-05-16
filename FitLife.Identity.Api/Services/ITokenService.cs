using FitLife.Identity.Api.DTOs;
using FitLife.Identity.Api.Models;

namespace FitLife.Identity.Api.Services;

public interface ITokenService
{
    TokenResponse GenerateToken(ApplicationUser user, IList<string> roles);
}
