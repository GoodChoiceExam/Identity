namespace FitLife.Identity.Api.DTOs;

public record RegisterRequest(string FullName, string Email, string Password);