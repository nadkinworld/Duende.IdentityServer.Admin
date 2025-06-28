using System;
using System.Collections.Generic;

namespace Skoruba.Duende.IdentityServer.STS.Identity.Models;

public class UserPermission
{
    public Guid Id { get; set; }
    public string UserId { get; set; }
    public List<string> Permissions { get; set; } = new();
    public DateTime CachedAt { get; set; } = DateTime.UtcNow;
}
