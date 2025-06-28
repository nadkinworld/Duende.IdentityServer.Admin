using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Skoruba.Duende.IdentityServer.Admin.EntityFramework.Shared.Entities.Identity;


namespace Skoruba.Duende.IdentityServer.STS.Identity.Seeder
{
    public class ClaimRoleSeedData
    {
        public string Role { get; set; }
        public List<string> Claims { get; set; }
    }

    public static class RoleClaimSeeder
    {
        public static async Task SeedAsync(IServiceProvider serviceProvider, string claimsJsonPath)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<UserIdentityRole>>();

            // خواندن فایل claims.json
            var json = await File.ReadAllTextAsync(claimsJsonPath);
            var claimRoles = JsonSerializer.Deserialize<List<ClaimRoleSeedData>>(json);

            if (claimRoles == null) return;

            foreach (var claimRole in claimRoles)
            {
                // اگر رول وجود نداشت، ایجادش کن
                var role = await roleManager.FindByNameAsync(claimRole.Role);
                if (role == null)
                {
                    role = new UserIdentityRole { Name = claimRole.Role };
                    await roleManager.CreateAsync(role);
                }

                // اضافه کردن کلیم‌ها به رول
                var existingClaims = await roleManager.GetClaimsAsync(role);
                foreach (var claim in claimRole.Claims)
                {
                    if (!existingClaims.Any(c => c.Type == "Permission" && c.Value == claim))
                    {
                        await roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("role", claim));
                    }
                }
            }
        }
    }
}