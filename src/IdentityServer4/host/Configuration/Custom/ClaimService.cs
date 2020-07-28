using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using IdentityServer4;
//using Microsoft.AspNetCore.WebSockets.Internal;
using DAL.Core;
using Entities;
using IdentityServer4.Extensions;

namespace Host.Configuration.Custom
{
    public class ClaimsService : IClaimsService
    {

        /// <summary>
        /// The logger
        /// </summary>
        protected readonly ILogger Logger;

        /// <summary>
        /// The user service
        /// </summary>
        protected readonly IProfileService Profile;
        protected readonly IUnitOfWork uow;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultClaimsService"/> class.
        /// </summary>
        /// <param name="profile">The profile service</param>
        /// <param name="logger">The logger</param>
        public ClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger, IUnitOfWork unitOfWork)
        {
            Logger = logger;
            Profile = profile;
            uow = unitOfWork;
        }

        /// <summary>
        /// Returns claims for an identity token
        /// </summary>
        /// <param name="subject">The subject</param>
        /// <param name="resources">The requested resources</param>
        /// <param name="includeAllIdentityClaims">Specifies if all claims should be included in the token, or if the userinfo endpoint can be used to retrieve them</param>
        /// <param name="request">The raw request</param>
        /// <returns>
        /// Claims for the identity token
        /// </returns>
        public async virtual Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(ClaimsPrincipal subject, IdentityServer4.Models.Resources resources, bool includeAllIdentityClaims, ValidatedRequest request)
        {
            Logger.LogDebug("Getting custom claims for identity token for subject: {subject} and client: {clientId}",
                subject.GetSubjectId(),
                request.Client.ClientId);

            var outputClaims = new List<Claim>(GetStandardSubjectClaims(subject));
            outputClaims.AddRange(GetOptionalClaims(subject));

            
            // fetch all identity claims that need to go into the id token
            if (includeAllIdentityClaims || request.Client.AlwaysIncludeUserClaimsInIdToken)
            {

            }
            else
            {
                Logger.LogDebug("In addition to an id_token, an access_token was requested. No claims other than sub are included in the id_token. To obtain more user claims, either use the user info endpoint or set AlwaysIncludeUserClaimsInIdToken on the client configuration.");
            }

            return outputClaims;
        }

        /// <summary>
        /// Returns claims for an identity token.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="resources">The requested resources</param>
        /// <param name="request">The raw request.</param>
        /// <returns>
        /// Claims for the access token
        /// </returns>
        public async virtual Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsPrincipal subject, IdentityServer4.Models.Resources resources, ValidatedRequest request)
        {
            Logger.LogDebug("Getting claims for access token for client: {clientId}", request.Client.ClientId);

            // add client_id
            var outputClaims = new List<Claim>
            {
                new Claim(JwtClaimTypes.ClientId, request.Client.ClientId)
            };

            // check for client claims
            if (request.ClientClaims != null && request.ClientClaims.Any())
            {
                if (subject == null || request.Client.AlwaysSendClientClaims)
                {
                    foreach (var claim in request.ClientClaims)
                    {
                        var claimType = claim.Type;

                        if (!string.IsNullOrWhiteSpace(request.Client.ClientClaimsPrefix))
                        {
                            claimType = request.Client.ClientClaimsPrefix + claimType;
                        }

                        outputClaims.Add(new Claim(claimType, claim.Value, claim.ValueType));
                    }
                }
            }

            // add scopes
            foreach (var scope in resources.IdentityResources)
            {
                outputClaims.Add(new Claim(JwtClaimTypes.Scope, scope.Name));
            }
            foreach (var scope in resources.ApiResources.SelectMany(x => x.Scopes))
            {
                outputClaims.Add(new Claim(JwtClaimTypes.Scope, scope.Name));
            }

            // a user is involved
            if (subject != null)
            {
                if (resources.OfflineAccess)
                {
                    outputClaims.Add(new Claim(JwtClaimTypes.Scope, IdentityServerConstants.StandardScopes.OfflineAccess));
                }

                Logger.LogDebug("Getting claims for access token for subject: {subject}", subject.GetSubjectId());

                outputClaims.AddRange(GetStandardSubjectClaims(subject));
                outputClaims.AddRange(GetOptionalClaims(subject));

                // fetch all resource claims that need to go into the access token
                var additionalClaimTypes = new List<string>();
                foreach (var api in resources.ApiResources)
                {
                    // add claims configured on api resource
                    if (api.UserClaims != null)
                    {
                        foreach (var claim in api.UserClaims)
                        {
                            additionalClaimTypes.Add(claim);
                        }
                    }

                    // add claims configured on scope
                    foreach (var scope in api.Scopes)
                    {
                        if (scope.UserClaims != null)
                        {
                            foreach (var claim in scope.UserClaims)
                            {
                                additionalClaimTypes.Add(claim);
                            }
                        }
                    }
                }

                // filter so we don't ask for claim types that we will eventually filter out
                additionalClaimTypes = FilterRequestedClaimTypes(additionalClaimTypes).ToList();

                var context = new ProfileDataRequestContext(
                    subject,
                    request.Client,
                    IdentityServerConstants.ProfileDataCallers.ClaimsProviderAccessToken,
                    additionalClaimTypes.Distinct());
                context.RequestedResources = resources;

                await Profile.GetProfileDataAsync(context);

                var claims = FilterProtocolClaims(context.IssuedClaims);
                if (claims != null)
                {
                    outputClaims.AddRange(claims);
                }
            }

            var userId = subject.Claims.FirstOrDefault(x => x.Type == "sub");

            if (!string.IsNullOrEmpty(userId?.Value) && long.Parse(userId.Value) > 0)
            {
                int Id = int.Parse(userId.Value);
                
                WebApi.Services.SecurityService ss = new WebApi.Services.SecurityService(uow);
                var user = ss.GetUserWithRolesAndApis(Id);

                if (user.ErrorCode == -1)
                {
                    outputClaims.AddRange(user.Result.UserRole.Select(x => new Claim(JwtClaimTypes.Role, x.Id.ToString())).ToList());
                    outputClaims.Add(new Claim(JwtClaimTypes.Email, user.Result.Email));
                    outputClaims.Add(new Claim(JwtClaimTypes.Name, (user.Result.Name==null)?"":user.Result.Name));

                    List<Claim> claims = new List<Claim>();
                    foreach (UserRole ur in user.Result.UserRole)
                    {
                        claims.AddRange(ur.Role.RoleApi.Select(y => new Claim("Api", y.Api.Name)));
                    }
                    outputClaims.AddRange(claims.Distinct());
                }
                else
                {
                    throw new Exception("User profile not found.");
                }
            }

            return outputClaims;
        }

        /// <summary>
        /// Gets the standard subject claims.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns>A list of standard claims</returns>
        protected virtual IEnumerable<Claim> GetStandardSubjectClaims(ClaimsPrincipal subject)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, subject.GetSubjectId()),
                new Claim(JwtClaimTypes.AuthenticationTime, subject.GetAuthenticationTimeEpoch().ToString(), ClaimValueTypes.Integer),
                new Claim(JwtClaimTypes.IdentityProvider, subject.GetIdentityProvider())
            };

            claims.AddRange(subject.GetAuthenticationMethods());

            return claims;
        }

        /// <summary>
        /// Gets additional (and optional) claims from the cookie or incoming subject.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns>Additional claims</returns>
        protected virtual IEnumerable<Claim> GetOptionalClaims(ClaimsPrincipal subject)
        {
            var claims = new List<Claim>();

            var acr = subject.FindFirst(JwtClaimTypes.AuthenticationContextClassReference);
            if (acr != null) claims.Add(acr);

            return claims;
        }

        /// <summary>
        /// Filters out protocol claims like amr, nonce etc..
        /// </summary>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        protected virtual IEnumerable<Claim> FilterProtocolClaims(IEnumerable<Claim> claims)
        {
            var claimsToFilter = claims.Where(x => ClaimsServiceFilterClaimTypes.Contains(x.Type));
            if (claimsToFilter.Any())
            {
                var types = claimsToFilter.Select(x => x.Type);
                Logger.LogDebug("Claim types from profile service that were filtered: {claimTypes}", types);
            }
            return claims.Except(claimsToFilter);
        }

        /// <summary>
        /// Filters out protocol claims like amr, nonce etc..
        /// </summary>
        /// <param name="claimTypes">The claim types.</param>
        protected virtual IEnumerable<string> FilterRequestedClaimTypes(IEnumerable<string> claimTypes)
        {
            var claimTypesToFilter = claimTypes.Where(x => ClaimsServiceFilterClaimTypes.Contains(x));
            return claimTypes.Except(claimTypesToFilter);
        }

        public readonly string[] ClaimsServiceFilterClaimTypes = {
                // TODO: consider JwtClaimTypes.AuthenticationContextClassReference,
                JwtClaimTypes.AccessTokenHash,
                JwtClaimTypes.Audience,
                JwtClaimTypes.AuthenticationMethod,
                JwtClaimTypes.AuthenticationTime,
                JwtClaimTypes.AuthorizedParty,
                JwtClaimTypes.AuthorizationCodeHash,
                JwtClaimTypes.ClientId,
                JwtClaimTypes.Expiration,
                JwtClaimTypes.IdentityProvider,
                JwtClaimTypes.IssuedAt,
                JwtClaimTypes.Issuer,
                JwtClaimTypes.JwtId,
                JwtClaimTypes.Nonce,
                JwtClaimTypes.NotBefore,
                JwtClaimTypes.ReferenceTokenId,
                JwtClaimTypes.SessionId,
                JwtClaimTypes.Subject,
                JwtClaimTypes.Scope,
                JwtClaimTypes.Confirmation
            };
    }
}
