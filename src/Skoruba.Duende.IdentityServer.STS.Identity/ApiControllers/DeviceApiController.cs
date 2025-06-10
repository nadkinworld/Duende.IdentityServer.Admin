using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Skoruba.Duende.IdentityServer.STS.Identity.ApiViewModels;
using System.Linq;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiControllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Authorize]
    public class DeviceApiController : ControllerBase
    {
        private readonly IDeviceFlowInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IResourceStore _resourceStore;

        public DeviceApiController(
            IDeviceFlowInteractionService interaction,
            IClientStore clientStore,
            IResourceStore resourceStore)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _resourceStore = resourceStore;
        }

        /// <summary>
        /// Get device authorization request
        /// </summary>
        [HttpGet("{userCode}")]
        [ProducesResponseType(typeof(DeviceAuthorizationResponse), 200)]
        [ProducesResponseType(typeof(DeviceAuthorizationErrorResponse), 400)]
        public async Task<IActionResult> GetDeviceAuthorization(string userCode)
        {
            var request = await _interaction.GetAuthorizationContextAsync(userCode);
            if (request == null)
            {
                return BadRequest(new DeviceAuthorizationErrorResponse { Error = "Invalid user code" });
            }

            var client = await _clientStore.FindClientByIdAsync(request.Client.ClientId);
            if (client == null)
            {
                return BadRequest(new DeviceAuthorizationErrorResponse { Error = "Invalid client" });
            }

            var resources = await _resourceStore.FindResourcesByScopeAsync(request.ValidatedResources.RawScopeValues);

            return Ok(new DeviceAuthorizationResponse
            {
                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                ClientLogoUrl = client.LogoUri,
                AllowRememberConsent = client.AllowRememberConsent,
                IdentityScopes = resources.IdentityResources.Select(x => new ScopeViewModel
                {
                    Name = x.Name,
                    DisplayName = x.DisplayName ?? x.Name,
                    Description = x.Description,
                    Emphasize = x.Emphasize,
                    Required = x.Required
                }).ToArray(),
                ApiScopes = resources.ApiScopes.Select(x => new ScopeViewModel
                {
                    Name = x.Name,
                    DisplayName = x.DisplayName ?? x.Name,
                    Description = x.Description,
                    Emphasize = x.Emphasize,
                    Required = x.Required
                }).ToArray()
            });
        }

        ///// <summary>
        ///// Handle device authorization callback
        ///// </summary>
        //[HttpPost("callback")]
        //[ProducesResponseType(typeof(DeviceAuthorizationCallbackResponse), 200)]
        //[ProducesResponseType(typeof(DeviceAuthorizationErrorResponse), 400)]
        //public async Task<IActionResult> Callback([FromBody] DeviceAuthorizationCallbackViewModel model)
        //{
        //    if (model == null)
        //    {
        //        return BadRequest(new DeviceAuthorizationErrorResponse { Error = "Invalid request" });
        //    }

        //    var result = await _interaction.HandleRequestAsync(model.UserCode, model);
        //    if (result.IsError)
        //    {
        //        return BadRequest(new DeviceAuthorizationErrorResponse { Error = result.Error });
        //    }

        //    return Ok(new DeviceAuthorizationCallbackResponse { Success = true });
        //}
    }

    public class DeviceAuthorizationResponse
    {
        public string ClientName { get; set; }
        public string ClientUrl { get; set; }
        public string ClientLogoUrl { get; set; }
        public bool AllowRememberConsent { get; set; }
        public ScopeViewModel[] IdentityScopes { get; set; }
        public ScopeViewModel[] ApiScopes { get; set; }
    }

    public class DeviceAuthorizationErrorResponse
    {
        public string Error { get; set; }
    }

    public class DeviceAuthorizationCallbackResponse
    {
        public bool Success { get; set; }
    }
} 