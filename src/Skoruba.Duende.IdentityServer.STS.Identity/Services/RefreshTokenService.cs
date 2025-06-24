using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Skoruba.Duende.IdentityServer.STS.Identity.Configuration;
using Skoruba.Duende.IdentityServer.STS.Identity.Models;

namespace Skoruba.Duende.IdentityServer.STS.Identity.Services
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly ConcurrentDictionary<string, RefreshToken> _refreshTokens = new();

        public RefreshTokenService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public Task<string> GenerateRefreshTokenAsync(string userId)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var refreshToken = new RefreshToken
            {
                Token = token,
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays),
                IsRevoked = false
            };
            _refreshTokens[token] = refreshToken;
            return Task.FromResult(token);
        }

        public Task<bool> ValidateRefreshTokenAsync(string refreshToken, string userId)
        {
            if (_refreshTokens.TryGetValue(refreshToken, out var tokenInfo))
            {
                if (!tokenInfo.IsRevoked && tokenInfo.UserId == userId && tokenInfo.ExpiresAt > DateTime.UtcNow)
                    return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }

        public Task<string> GetUserIdFromRefreshTokenAsync(string refreshToken)
        {
            if (_refreshTokens.TryGetValue(refreshToken, out var tokenInfo))
            {
                if (!tokenInfo.IsRevoked && tokenInfo.ExpiresAt > DateTime.UtcNow)
                    return Task.FromResult(tokenInfo.UserId);
            }
            return Task.FromResult<string>(null);
        }

        public Task RevokeRefreshTokenAsync(string refreshToken)
        {
            if (_refreshTokens.TryGetValue(refreshToken, out var tokenInfo))
            {
                tokenInfo.IsRevoked = true;
                _refreshTokens[refreshToken] = tokenInfo;
            }
            return Task.CompletedTask;
        }
    }
}