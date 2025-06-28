using System;
using System.Threading.Tasks;

namespace Skoruba.Duende.IdentityServer.STS.Identity.Services
{
    public interface IRefreshTokenService
    {
        Task<string> GenerateRefreshTokenAsync(string userId);
        Task<bool> ValidateRefreshTokenAsync(string refreshToken, string userId);
        Task<string> GetUserIdFromRefreshTokenAsync(string refreshToken);
        Task RevokeRefreshTokenAsync(string refreshToken);
        Task InvalidateUserPermissionCacheAsync(Guid userId);
    }
}