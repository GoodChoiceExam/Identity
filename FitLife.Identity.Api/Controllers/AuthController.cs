using FitLife.Identity.Api.DTOs;
using FitLife.Identity.Api.Models;
using FitLife.Identity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FitLife.Identity.Api.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;

    public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FullName = request.FullName
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        await _userManager.AddToRoleAsync(user, "Member");
        var roles = await _userManager.GetRolesAsync(user);
        return Ok(_tokenService.GenerateToken(user, roles));
    }

    [Authorize(Roles = "Trainer")]
    [HttpPost("register-trainer")]
    public async Task<IActionResult> RegisterTrainer(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FullName = request.FullName
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);
        
        await _userManager.AddToRoleAsync(user, "Trainer");
        var roles = await _userManager.GetRolesAsync(user);
        return Ok(_tokenService.GenerateToken(user, roles));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
            return Unauthorized("Invalid credentials");

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(_tokenService.GenerateToken(user, roles));
    }
}