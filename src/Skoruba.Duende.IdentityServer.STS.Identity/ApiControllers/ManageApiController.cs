using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Skoruba.Duende.IdentityServer.STS.Identity.ApiViewModels;
using Skoruba.Duende.IdentityServer.STS.Identity.Helpers.Localization;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiControllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Authorize]
    public class ManageApiController<TUser, TKey> : ControllerBase
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly UserManager<TUser> _userManager;
        private readonly SignInManager<TUser> _signInManager;
        private readonly IGenericControllerLocalizer<ManageApiController<TUser, TKey>> _localizer;
        private readonly ILogger<ManageApiController<TUser, TKey>> _logger;

        public ManageApiController(
            UserManager<TUser> userManager,
            SignInManager<TUser> signInManager,
            IGenericControllerLocalizer<ManageApiController<TUser, TKey>> localizer,
            ILogger<ManageApiController<TUser, TKey>> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _localizer = localizer;
            _logger = logger;
        }

        /// <summary>
        /// Get user profile information
        /// </summary>
        [HttpGet("profile")]
        [ProducesResponseType(typeof(UserProfileResponse), 200)]
        public async Task<IActionResult> GetProfile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            return Ok(new UserProfileResponse
            {
                Username = user.UserName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                IsEmailConfirmed = user.EmailConfirmed,
                IsPhoneNumberConfirmed = user.PhoneNumberConfirmed
            });
        }

        /// <summary>
        /// Update user profile information
        /// </summary>
        [HttpPut("profile")]
        [ProducesResponseType(typeof(UpdateProfileResponse), 200)]
        [ProducesResponseType(typeof(UpdateProfileErrorResponse), 400)]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new UpdateProfileErrorResponse { Error = "Invalid model state" });
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            user.Email = model.Email;
            user.PhoneNumber = model.PhoneNumber;

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                await _signInManager.RefreshSignInAsync(user);
                return Ok(new UpdateProfileResponse { Success = true });
            }

            return BadRequest(new UpdateProfileErrorResponse { Errors = result.Errors });
        }

        /// <summary>
        /// Change user password
        /// </summary>
        [HttpPost("change-password")]
        [ProducesResponseType(typeof(ChangePasswordResponse), 200)]
        [ProducesResponseType(typeof(ChangePasswordErrorResponse), 400)]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ChangePasswordErrorResponse { Error = "Invalid model state" });
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                await _signInManager.RefreshSignInAsync(user);
                _logger.LogInformation("User changed their password successfully.");
                return Ok(new ChangePasswordResponse { Success = true });
            }

            return BadRequest(new ChangePasswordErrorResponse { Errors = result.Errors });
        }
    }

    public class UserProfileResponse
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public bool IsPhoneNumberConfirmed { get; set; }
    }

    public class UpdateProfileResponse
    {
        public bool Success { get; set; }
    }

    public class UpdateProfileErrorResponse
    {
        public string Error { get; set; }
        public IEnumerable<IdentityError> Errors { get; set; }
    }

    public class ChangePasswordResponse
    {
        public bool Success { get; set; }
    }

    public class ChangePasswordErrorResponse
    {
        public string Error { get; set; }
        public IEnumerable<IdentityError> Errors { get; set; }
    }
} 