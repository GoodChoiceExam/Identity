using FitLife.Identity.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace FitLife.Identity.Api.Controllers;

[ApiController]
public class JwksController : ControllerBase
{
    private readonly ITokenService _tokenService;

    public JwksController(ITokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpGet(".well-known/jwks.json")]
    public IActionResult GetJwks() => Ok(_tokenService.GetJsonWebKeySet());
}