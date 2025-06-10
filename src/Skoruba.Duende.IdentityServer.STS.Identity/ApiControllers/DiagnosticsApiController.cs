using System;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiControllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Authorize]
    public class DiagnosticsApiController : ControllerBase
    {
        /// <summary>
        /// Get current user claims
        /// </summary>
        [HttpGet("claims")]
        [ProducesResponseType(typeof(ClaimsResponse), 200)]
        public IActionResult GetClaims()
        {
            var claims = User.Claims.Select(c => new ClaimViewModel
            {
                Type = c.Type,
                Value = c.Value
            }).ToArray();

            return Ok(new ClaimsResponse { Claims = claims });
        }

        /// <summary>
        /// Get current user authentication info
        /// </summary>
        [HttpGet("auth")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        public IActionResult GetAuth()
        {
            return Ok(new AuthResponse
            {
                IsAuthenticated = User.Identity.IsAuthenticated,
                AuthenticationType = User.Identity.AuthenticationType,
                Name = User.Identity.Name
            });
        }
    }

    public class ClaimsResponse
    {
        public ClaimViewModel[] Claims { get; set; }
    }

    public class ClaimViewModel
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    public class AuthResponse
    {
        public bool IsAuthenticated { get; set; }
        public string AuthenticationType { get; set; }
        public string Name { get; set; }
    }
} 