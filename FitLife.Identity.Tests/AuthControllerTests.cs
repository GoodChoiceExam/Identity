using FitLife.Identity.Api.Controllers;
using FitLife.Identity.Api.DTOs;
using FitLife.Identity.Api.Models;
using FitLife.Identity.Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

namespace FitLife.Identity.Tests;

[TestFixture]
public class AuthControllerTests
{
    private Mock<UserManager<ApplicationUser>> _userManager = null!;
    private Mock<ITokenService> _tokenService = null!;
    private AuthController _sut = null!;

    [SetUp]
    public void Setup()
    {
        var store = new Mock<IUserStore<ApplicationUser>>();
        _userManager = new Mock<UserManager<ApplicationUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        _tokenService = new Mock<ITokenService>();
        var logger = new Mock<ILogger<AuthController>>();
        var config = new Mock<IConfiguration>();
        _sut = new AuthController(_userManager.Object, _tokenService.Object, logger.Object, config.Object);
    }

    [Test]
    public async Task Register_ValidData_ReturnsOkWithToken()
    {
        var request = new RegisterRequest("Test Bruger", "test@fitlife.dk", "Test1234!");
        var expectedToken = new TokenResponse("jwt", DateTime.UtcNow.AddHours(1));

        _userManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);
        _userManager.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Member"))
            .ReturnsAsync(IdentityResult.Success);
        _userManager.Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(["Member"]);
        _tokenService.Setup(x => x.GenerateToken(It.IsAny<ApplicationUser>(), It.IsAny<IList<string>>()))
            .Returns(expectedToken);

        var result = await _sut.Register(request);

        Assert.That(result, Is.InstanceOf<OkObjectResult>());
        Assert.That(((OkObjectResult)result).Value, Is.EqualTo(expectedToken));
    }

    [Test]
    public async Task Register_DuplicateEmail_ReturnsBadRequest()
    {
        var request = new RegisterRequest("Test Bruger", "dup@fitlife.dk", "Test1234!");

        _userManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Duplicate" }));

        var result = await _sut.Register(request);

        Assert.That(result, Is.InstanceOf<BadRequestObjectResult>());
    }

    [Test]
    public async Task Login_ValidCredentials_ReturnsOkWithToken()
    {
        var request = new LoginRequest("test@fitlife.dk", "Test1234!");
        var user = new ApplicationUser { Email = request.Email, FullName = "Test Bruger" };
        var expectedToken = new TokenResponse("jwt", DateTime.UtcNow.AddHours(1));

        _userManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
        _userManager.Setup(x => x.CheckPasswordAsync(user, request.Password)).ReturnsAsync(true);
        _userManager.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["Member"]);
        _tokenService.Setup(x => x.GenerateToken(user, It.IsAny<IList<string>>())).Returns(expectedToken);

        var result = await _sut.Login(request);

        Assert.That(result, Is.InstanceOf<OkObjectResult>());
    }

    [Test]
    public async Task Login_WrongPassword_ReturnsUnauthorized()
    {
        var request = new LoginRequest("test@fitlife.dk", "Forkert!");
        var user = new ApplicationUser { Email = request.Email };

        _userManager.Setup(x => x.FindByEmailAsync(request.Email)).ReturnsAsync(user);
        _userManager.Setup(x => x.CheckPasswordAsync(user, request.Password)).ReturnsAsync(false);

        var result = await _sut.Login(request);

        Assert.That(result, Is.InstanceOf<UnauthorizedObjectResult>());
    }

    [Test]
    public async Task Login_UnknownEmail_ReturnsUnauthorized()
    {
        var request = new LoginRequest("ingen@fitlife.dk", "Test1234!");

        _userManager.Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _sut.Login(request);

        Assert.That(result, Is.InstanceOf<UnauthorizedObjectResult>());
    }
    
    [Test]
    public async Task RegisterTrainer_ValidData_ReturnsOk()
    {
        var request = new RegisterRequest("Træner Hansen", "trainer@fitlife.dk", "Test1234!");

        _userManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);
        _userManager.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), "Trainer"))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _sut.RegisterTrainer(request);

        Assert.That(result, Is.InstanceOf<OkObjectResult>());
    }

    [Test]
    public async Task RegisterTrainer_DuplicateEmail_ReturnsBadRequest()
    {
        var request = new RegisterRequest("Træner Hansen", "dup@fitlife.dk", "Test1234!");

        _userManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Duplicate" }));

        var result = await _sut.RegisterTrainer(request);

        Assert.That(result, Is.InstanceOf<BadRequestObjectResult>());
    }
}