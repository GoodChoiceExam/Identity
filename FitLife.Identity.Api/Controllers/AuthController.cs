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
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

    public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService, ILogger<AuthController> logger, IConfiguration config)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _logger = logger;
        _config = config;
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

    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
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
        _logger.LogInformation("Trainer user created with UserId {UserId} by admin", user.Id);
        return Ok(new { userId = user.Id, email = user.Email, fullName = user.FullName });
    }

    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    [HttpPost("register-admin")]
    public async Task<IActionResult> RegisterAdmin(RegisterRequest request)
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

        await _userManager.AddToRoleAsync(user, "Admin");
        _logger.LogInformation("Admin user created with UserId {UserId} by admin", user.Id);
        return Ok(new { userId = user.Id, email = user.Email, fullName = user.FullName });
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

    [HttpGet("service")]
    public IActionResult GetService()
    {
        var isFail = _config["ToFail"] == "yes";
        var hostname = System.Net.Dns.GetHostName();
        var seconds = DateTime.Now.Second;
        var hasError = seconds > 30 && seconds < 45;

        _logger.LogDebug("Fail condition for {Hostname} is set to {IsFail}", hostname, isFail);

        if (hasError && isFail)
            return StatusCode(503);

        return Ok(new { hostname, seconds });
    }

    [HttpGet("version")]
    public async Task<Dictionary<string, string>> GetVersion()
    {
        var properties = new Dictionary<string, string>();
        properties.Add("service", "FitLife Identity API");
        var ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(typeof(Program).Assembly.Location).ProductVersion;
        properties.Add("version", ver!);
        try
        {
            var hostName = System.Net.Dns.GetHostName();
            var ips = await System.Net.Dns.GetHostAddressesAsync(hostName);
            var ipa = ips.First().MapToIPv4().ToString();
            properties.Add("hosted-at-address", ipa);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            properties.Add("hosted-at-address", "Could not resolve IP-address");
        }
        return properties;
    }
}