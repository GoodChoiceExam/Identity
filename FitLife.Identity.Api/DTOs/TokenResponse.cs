namespace FitLife.Identity.Api.DTOs;

public record TokenResponse(string AccessToken, DateTime ExpiresAt);