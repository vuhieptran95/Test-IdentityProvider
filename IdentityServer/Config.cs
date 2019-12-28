// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource("location",new string[] {"location"})
            };

        public static IEnumerable<ApiResource> Apis =>
            new ApiResource[]
            {
            };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                    {
                        ClientId = "mvc",
                        ClientSecrets = { new Secret("secret".Sha256()) },

                        AllowedGrantTypes = GrantTypes.Code,
                        RequireConsent = true,

                        RedirectUris = { "http://localhost:5011/signin-oidc" },

                        AlwaysIncludeUserClaimsInIdToken = true,

                        AllowedScopes = new List<string>
                        {
                            IdentityServerConstants.StandardScopes.OpenId,
                            IdentityServerConstants.StandardScopes.Profile,
                            IdentityServerConstants.StandardScopes.Email,
                            "location"
                        },

                        AlwaysIncludeUserClaimsInIdToken = true
                    }
            };

    }
}