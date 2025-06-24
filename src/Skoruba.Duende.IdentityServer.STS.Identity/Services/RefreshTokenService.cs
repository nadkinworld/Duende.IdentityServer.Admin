using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AccessIO.Framework.Common.Cache;
using Microsoft.Extensions.Options;
using Skoruba.Duende.IdentityServer.STS.Identity.Configuration;
using Skoruba.Duende.IdentityServer.STS.Identity.Models;
using Skoruba.Duende.IdentityServer.STS.Identity.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly IDistributedCacheService _cacheService;
    private readonly JwtSettings _jwtSettings;

    public RefreshTokenService(
        IOptions<JwtSettings> jwtSettings,
        IDistributedCacheService cacheService)
    {
        _jwtSettings = jwtSettings.Value;
        _cacheService = cacheService;
    }

    private string GetRefreshTokenKey(string token) => $"refresh_token:{token}";

    public async Task<string> GenerateRefreshTokenAsync(string userId)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var refreshToken = new RefreshToken
        {
            Id = new Guid(userId),
            Token = token,
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays),
            IsRevoked = false
        };
        var key = GetRefreshTokenKey(token);
        var result = await _cacheService.CreateAsync<RefreshToken>(refreshToken, refreshToken.ExpiresAt - DateTime.UtcNow);
        return token;
    }

    public async Task<bool> ValidateRefreshTokenAsync(string refreshToken, string userId)
    {
        var key = GetRefreshTokenKey(refreshToken);
        var result = await _cacheService.FirstByAsync<RefreshToken>(x => x.Token == refreshToken);
        if (!result.IsSuccess || result.Value == null)
            return false;

        var tokenInfo = result.Value;
        if (tokenInfo.IsRevoked || tokenInfo.UserId != userId || tokenInfo.ExpiresAt < DateTime.UtcNow)
            return false;

        return true;
    }

    public async Task<string> GetUserIdFromRefreshTokenAsync(string refreshToken)
    {
        var result = await _cacheService.FirstByAsync<RefreshToken>(x => x.Token == refreshToken);
        if (!result.IsSuccess || result.Value == null)
            return null;

        var tokenInfo = result.Value;
        if (tokenInfo.IsRevoked || tokenInfo.ExpiresAt < DateTime.UtcNow)
            return null;

        return tokenInfo.UserId;
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken)
    {
        var result = await _cacheService.FirstByAsync<RefreshToken>(x => x.Token == refreshToken);
        if (result.IsSuccess && result.Value != null)
        {
            var tokenInfo = result.Value;
            tokenInfo.IsRevoked = true;
            await _cacheService.UpdateAsync<RefreshToken>(x => x.Token == refreshToken, tokenInfo, tokenInfo.ExpiresAt - DateTime.UtcNow);
        }
    }
}