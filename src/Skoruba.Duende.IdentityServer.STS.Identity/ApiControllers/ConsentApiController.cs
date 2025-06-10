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
    public class ConsentApiController : ControllerBase
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IResourceStore _resourceStore;

        public ConsentApiController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IResourceStore resourceStore)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _resourceStore = resourceStore;
        }

        /// <summary>
        /// Get consent request
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(ConsentResponse), 200)]
        [ProducesResponseType(typeof(ConsentErrorResponse), 400)]
        public async Task<IActionResult> GetConsent([FromQuery] string returnUrl)
        {
            var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (request == null)
            {
                return BadRequest(new ConsentErrorResponse { Error = "Invalid return URL" });
            }

            var client = await _clientStore.FindClientByIdAsync(request.Client.ClientId);
            if (client == null)
            {
                return BadRequest(new ConsentErrorResponse { Error = "Invalid client" });
            }

            var resources = await _resourceStore.FindResourcesByScopeAsync(request.ValidatedResources.RawScopeValues);

            return Ok(new ConsentResponse
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
        ///// Process consent
        ///// </summary>
        //[HttpPost]
        //[ProducesResponseType(typeof(ConsentProcessResponse), 200)]
        //[ProducesResponseType(typeof(ConsentErrorResponse), 400)]
        //public async Task<IActionResult> ProcessConsent([FromBody] ConsentInputModel model)
        //{
        //    var result = await _interaction.GrantConsentAsync(model);
        //    if (result.IsError)
        //    {
        //        return BadRequest(new ConsentErrorResponse { Error = result.Error });
        //    }

        //    return Ok(new ConsentProcessResponse { ReturnUrl = result.RedirectUri });
        //}
    }

    public class ConsentResponse
    {
        public string ClientName { get; set; }
        public string ClientUrl { get; set; }
        public string ClientLogoUrl { get; set; }
        public bool AllowRememberConsent { get; set; }
        public ScopeViewModel[] IdentityScopes { get; set; }
        public ScopeViewModel[] ApiScopes { get; set; }
    }

    public class ConsentErrorResponse
    {
        public string Error { get; set; }
    }

    public class ConsentProcessResponse
    {
        public string ReturnUrl { get; set; }
    }
} 