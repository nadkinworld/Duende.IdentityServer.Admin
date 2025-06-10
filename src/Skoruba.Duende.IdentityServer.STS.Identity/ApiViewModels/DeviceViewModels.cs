using System.Collections.Generic;

namespace Skoruba.Duende.IdentityServer.STS.Identity.ApiViewModels
{
    public class DeviceAuthorizationCallbackViewModel
    {
        public string UserCode { get; set; }
        public string Button { get; set; }
        public IEnumerable<string> ScopesConsented { get; set; }
        public bool RememberConsent { get; set; }
    }
} 