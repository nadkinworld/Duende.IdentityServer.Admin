using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AccessIO.Framework.Common.Cache;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Skoruba.Duende.IdentityServer.Shared.Configuration.Configuration.Identity;
using Skoruba.Duende.IdentityServer.STS.Identity.ApiViewModels;
using Skoruba.Duende.IdentityServer.STS.Identity.Configuration;
using Skoruba.Duende.IdentityServer.STS.Identity.Helpers;
using Skoruba.Duende.IdentityServer.STS.Identity.Helpers.Localization;
using Skoruba.Duende.IdentityServer.STS.Identity.Models;
using IRefreshTokenService = Skoruba.Duende.IdentityServer.STS.Identity.Services.IRefreshTokenService;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiControllers;
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AccountApiController<TUser, TRole, TKey> : ControllerBase
    where TUser : IdentityUser<TKey>, new()
    where TRole : IdentityRole<TKey>, new()
    where TKey : IEquatable<TKey>
{
    private readonly UserResolver<TUser> _userResolver;
    private readonly UserManager<TUser> _userManager;
    private readonly RoleManager<TRole> _roleManager;
    private readonly ApplicationSignInManager<TUser> _signInManager;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IEventService _events;
    private readonly IEmailSender _emailSender;
    private readonly IGenericControllerLocalizer<AccountApiController<TUser, TRole, TKey>> _localizer;
    private readonly LoginConfiguration _loginConfiguration;
    private readonly RegisterConfiguration _registerConfiguration;
    private readonly IdentityOptions _identityOptions;
    private readonly ILogger<AccountApiController<TUser, TRole, TKey>> _logger;
    private readonly IDistributedCacheService _cacheService;
    private readonly JwtSettings _jwtSettings;
    public AccountApiController(
        UserResolver<TUser> userResolver,
        UserManager<TUser> userManager,
        RoleManager<TRole> roleManager,
        ApplicationSignInManager<TUser> signInManager,
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IEventService events,
        IEmailSender emailSender,
        IGenericControllerLocalizer<AccountApiController<TUser, TRole, TKey>> localizer,
        LoginConfiguration loginConfiguration,
        RegisterConfiguration registerConfiguration,
        IdentityOptions identityOptions,
        ILogger<AccountApiController<TUser, TRole, TKey>> logger,
        IOptions<JwtSettings> jwtSettings,
        IDistributedCacheService cacheService)
    {
        _userResolver = userResolver;
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _interaction = interaction;
        _clientStore = clientStore;
        _events = events;
        _emailSender = emailSender;
        _localizer = localizer;
        _loginConfiguration = loginConfiguration;
        _registerConfiguration = registerConfiguration;
        _identityOptions = identityOptions;
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
        _cacheService = cacheService;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginResponse), 200)]
    [ProducesResponseType(typeof(LoginErrorResponse), 400)]
    public async Task<IActionResult> Login([FromBody] LoginInputModel model, [FromServices] IRefreshTokenService refreshTokenService)
    {
        if (ModelState.IsValid)
        {
            var user = await _userResolver.GetUserAsync(model.Username);
            if (user != default(TUser))
            {
                var userId = user.Id.ToString();
                var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    await refreshTokenService.InvalidateUserPermissionCacheAsync(new Guid(User.GetSubjectId()));
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, userId, user.UserName));
                    var roles = await _userManager.GetRolesAsync(user);
                    var token = GenerateToken(userId, user.UserName, roles);

                    var permissions = await GetPermissionsAsync(roles);
                    var key = GetPermissionCacheKey(userId);
                    var permissionModel = new UserPermission
                    {
                        Id = new Guid(userId),
                        UserId = userId,
                        Permissions = permissions,
                        CachedAt = DateTime.UtcNow,
                    };
                    await _cacheService.CreateAsync(permissionModel);

                    var refreshToken = await refreshTokenService.GenerateRefreshTokenAsync(userId);

                    return Ok(new LoginResponse
                    {
                        Success = true,
                        ReturnUrl = model.ReturnUrl,
                        Token = token,
                        RefreshToken = refreshToken,
                        UserName = user.UserName,
                        Email = user.Email
                    });
                }

                if (result.IsLockedOut)
                {
                    return BadRequest(new LoginErrorResponse { Error = "Account locked out" });
                }
            }
            await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));
            return BadRequest(new LoginErrorResponse { Error = "Invalid username or password" });
        }

        return BadRequest(new LoginErrorResponse { Error = "Invalid model state" });
    }

    [HttpPost("refreshToken")]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model, [FromServices] IRefreshTokenService refreshTokenService)
    {
        var userId = await refreshTokenService.GetUserIdFromRefreshTokenAsync(model.RefreshToken);
        if (userId == null)
            return BadRequest(new { error = "Invalid refresh token" });

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return BadRequest(new { error = "User not found" });

        var isValid = await refreshTokenService.ValidateRefreshTokenAsync(model.RefreshToken, userId);
        if (!isValid)
            return BadRequest(new { error = "Invalid or expired refresh token" });

        await refreshTokenService.InvalidateUserPermissionCacheAsync(new Guid(User.GetSubjectId()));
        var roles = await _userManager.GetRolesAsync(user);
        var newToken = GenerateToken(user.Id.ToString(), user.UserName, roles);

        var permissions = await GetPermissionsAsync(roles);
        var key = GetPermissionCacheKey(userId);
        var permissionModel = new UserPermission
        {
            Id = new Guid(userId),
            UserId = userId,
            Permissions = permissions,
            CachedAt = DateTime.UtcNow,
        };
        await _cacheService.CreateAsync(permissionModel);

        var newRefreshToken = await refreshTokenService.GenerateRefreshTokenAsync(user.Id.ToString());

        await refreshTokenService.RevokeRefreshTokenAsync(model.RefreshToken);

        return Ok(new
        {
            token = newToken,
            refreshToken = newRefreshToken
        });
    }


    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromBody] LogoutInputModel model, [FromServices] IRefreshTokenService refreshTokenService)
    {
        if (!string.IsNullOrEmpty(model.RefreshToken))
        {
            await refreshTokenService.RevokeRefreshTokenAsync(model.RefreshToken);
            await refreshTokenService.InvalidateUserPermissionCacheAsync(new Guid(User.GetSubjectId()));
        }

        await _signInManager.SignOutAsync();
        await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));

        return Ok(new LogoutResponse { Success = true });
    }


    private string GenerateToken(string userId, string username, IEnumerable<string> roles)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.UniqueName, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

        //foreach (var role in roles)
        //{
        //    claims.Add(new Claim(ClaimTypes.Role, role));

        //    var identityRole =  _roleManager.FindByNameAsync(role).Result;
        //    if (identityRole != null)
        //    {
        //        var roleClaims = _roleManager.GetClaimsAsync(identityRole).Result;

        //        foreach (var claim in roleClaims.Where(c => c.Type == "Permission"))
        //        {
        //            claims.Add(claim); // claim از نوع Permission
        //        }
        //    }
        //}
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<List<string>> GetPermissionsAsync(IEnumerable<string> roles)
    {
        var permissions = new List<string>();

        foreach (var role in roles)
        {
            var roleEntity = await _roleManager.FindByNameAsync(role);
            var roleClaims = await _roleManager.GetClaimsAsync(roleEntity);

            permissions.AddRange(roleClaims
                .Where(c => c.Type == "Permission")
                .Select(c => c.Value));
        }

        return permissions.Distinct().ToList();
    }

    private string GetPermissionCacheKey(string userId) => $"user-permissions:{userId}";


}


public class LoginResponse
{
    public bool Success { get; set; }
    public bool RequiresTwoFactor { get; set; }
    public string ReturnUrl { get; set; }
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public string UserName { get; set; }
    public string Email { get; set; }
}

public class LoginErrorResponse
{
    public string Error { get; set; }
}

public class RegisterResponse
{
    public bool Success { get; set; }
}

public class RegisterErrorResponse
{
    public string Error { get; set; }
    public IEnumerable<IdentityError> Errors { get; set; }
}

public class LogoutResponse
{
    public bool Success { get; set; }
}

