using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Skoruba.Duende.IdentityServer.STS.Identity.ViewModels.Grants;
using System.Collections.Generic;
using Duende.IdentityServer.Models;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiControllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [Authorize]
    public class GrantsApiController : ControllerBase
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clients;
        private readonly IResourceStore _resources;

        public GrantsApiController(
            IIdentityServerInteractionService interaction,
            IClientStore clients,
            IResourceStore resources)
        {
            _interaction = interaction;
            _clients = clients;
            _resources = resources;
        }

        /// <summary>
        /// Get all grants for the current user
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(GrantsResponse), 200)]
        public async Task<IActionResult> GetGrants()
        {
            var grants = await _interaction.GetAllUserGrantsAsync();
            var grantsList = await BuildGrantsListAsync(grants);

            return Ok(new GrantsResponse { Grants = grantsList });
        }

        /// <summary>
        /// Revoke a specific grant
        /// </summary>
        [HttpDelete("{clientId}")]
        [ProducesResponseType(typeof(RevokeGrantResponse), 200)]
        public async Task<IActionResult> RevokeGrant(string clientId)
        {
            await _interaction.RevokeUserConsentAsync(clientId);
            return Ok(new RevokeGrantResponse { Success = true });
        }

        private async Task<GrantViewModel[]> BuildGrantsListAsync(IEnumerable<Grant> grants)
        {
            var grantsList = new List<GrantViewModel>();

            foreach (var grant in grants)
            {
                var client = await _clients.FindClientByIdAsync(grant.ClientId);
                if (client != null)
                {
                    var resources = await _resources.FindResourcesByScopeAsync(grant.Scopes);

                    var item = new GrantViewModel
                    {
                        ClientId = client.ClientId,
                        ClientName = client.ClientName ?? client.ClientId,
                        ClientLogoUrl = client.LogoUri,
                        ClientUrl = client.ClientUri,
                        Description = grant.Description,
                        Created = grant.CreationTime,
                        Expires = grant.Expiration,
                        IdentityGrantNames = resources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                        ApiGrantNames = resources.ApiScopes.Select(x => x.DisplayName ?? x.Name).ToArray()
                    };

                    grantsList.Add(item);
                }
            }

            return grantsList.ToArray();
        }
    }

    public class GrantsResponse
    {
        public GrantViewModel[] Grants { get; set; }
    }

    public class RevokeGrantResponse
    {
        public bool Success { get; set; }
    }
} 