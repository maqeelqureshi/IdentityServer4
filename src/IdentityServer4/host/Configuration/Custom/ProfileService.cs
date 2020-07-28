using DAL.Core;
using Entities;
using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Host.Configuration.Custom
{
    public class ProfileService : IProfileService
    {
        IUnitOfWork uow;
        public ProfileService(IUnitOfWork unitofWork)
        {
            this.uow = unitofWork;
        }

        //services
        //private readonly IUserRepository _userRepository;

        //public ProfileService(IUserRepository userRepository)
        //{
        //    _userRepository = userRepository;
        //}

        //Get user profile date in terms of claims when calling /connect/userinfo
        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            try
            {
                var userId = context.Subject.Claims.FirstOrDefault(x => x.Type == "sub");

                if (!string.IsNullOrEmpty(userId?.Value) && long.Parse(userId.Value) > 0)
                    if (context.Caller == "ClaimsProviderIdentityToken")
                    {
                        WebApi.Services.SecurityService ss = new WebApi.Services.SecurityService(uow);
                        var user = ss.GetWithUserRoles(int.Parse(userId.Value));

                        if (user.ErrorCode == -1)
                        {
                            //                            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Scope, user.Result.Email));
                            context.IssuedClaims = user.Result.UserRole.Select(x => new Claim(JwtClaimTypes.Role, x.Id.ToString())).ToList();
                            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Email, user.Result.Email));
                            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Name, user.Result.Name));

                            //List<Claim> claims = new List<Claim>();
                            //foreach (UserRole ur in user.Result.UserRole)
                            //{
                            //    claims.AddRange(ur.Role.RoleApi.Select(y => new Claim(JwtClaimTypes.Role, y.Api.Name)));
                            //}
                            //context.IssuedClaims.AddRange(claims.Distinct());
                        }
                        else
                        {
                            throw new Exception("User profile not found.");
                        }

                        //context.IssuedClaims.AddRange();


                    }
                    else if (context.Caller == "UserInfoEndpoint")
                    {
                        WebApi.Services.SecurityService ss = new WebApi.Services.SecurityService(uow);
                        var user = ss.GetWithUserRoles(int.Parse(userId.Value));

                        context.IssuedClaims.Add(new Claim(JwtClaimTypes.Scope, user.Result.Email));
                        //var apis = user.Result.UserRole.Select(x => x.Role.RoleApi.Select(y => new Claim(JwtClaimTypes.Role, y.Api.Name)));

                        if (user.ErrorCode == -1)
                        {
                            context.IssuedClaims = user.Result.UserRole.Select(x => new Claim(JwtClaimTypes.Role, x.Id.ToString())).ToList();
                            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Email, user.Result.Email));
                            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Name, user.Result.Name));
                        }
                        else
                        {
                            throw new Exception("User profile not found.");
                        }
                    }


                //{

                //    if (user.ErrorCode == -1)
                //    {
                //        context.IssuedClaims = user.Result.UserRole.Select(x => new Claim(JwtClaimTypes.Role, x.Id.ToString())).ToList();
                //        context.IssuedClaims.Add(new Claim(JwtClaimTypes.Email, user.Result.Email));
                //        context.IssuedClaims.Add(new Claim(JwtClaimTypes.Name, user.Result.Name));
                //    }
                //    else
                //    {
                //        throw new Exception("User profile not found.");
                //    }

                //    //using (DAL.Persistence.UnitOfWork unitOfWork = new DAL.Persistence.UnitOfWork())
                //    //{
                //    //    Entities.User usr = unitOfWork.UserRepository.Get(userId.Value);
                //    //    if (usr != null)
                //    //    {
                //    //        IList<Entities.UserRole> userRoles = unitOfWork.UserRoleRepository.GetList("Where UserId=@UserId", new { UserId = usr.Id }).ToList();
                //    //        usr.UserRole = userRoles;
                //    //        string roleIds = string.Join(",", usr.UserRole.Select(x => x.RoleId.ToString()));
                //    //        //var invoices = connection.Query<Invoice>(sql, new { Kind = new[] { InvoiceKind.StoreInvoice, InvoiceKind.WebInvoice } }).ToList();
                //    //        IEnumerable<Role> roles = unitOfWork.RoleRepository.GetList("where id in @roles", new { roles = usr.UserRole.Select(x => x.RoleId) });
                //    //        //string claimRoles = string.Join(",", roles.Select(x => x.Name));
                //    //        //new List<Claim>
                //    //        //        {
                //    //        //            //new Claim(JwtClaimTypes.Name, usr.Name ?? ""),
                //    //        //            //new Claim(JwtClaimTypes.Email, usr.Email  ?? ""),
                //    //        //            new Claim(JwtClaimTypes.Role, claimRoles),
                //    //        //            //new Claim("scope", (user.Id == 1)? "Api.GetAll":"")
                //    //        //        };
                //    //    }
                //    //    else
                //    //    {
                //    //        throw new Exception("User profile not found.");
                //    //    }
                //    //}
                //}
            }
            catch (Exception ex)
            {
                //log your error
            }
        }

        //check if user account is active.
        public async Task IsActiveAsync(IsActiveContext context)
        {
            //try
            //{
            //    //get subject from context (set in ResourceOwnerPasswordValidator.ValidateAsync),
            //    var userId = context.Subject.Claims.FirstOrDefault(x => x.Type == "sub");

            //    if (!string.IsNullOrEmpty(userId?.Value) && long.Parse(userId.Value) > 0)
            //    {
            //        var user = new User();// await _userRepository.FindAsync(long.Parse(userId.Value));

            //        if (user != null)
            //        {
            //            if (user.Status == enUserStatus.Active)
            //            {
            //                context.IsActive = true;
            //            }
            //        }
            //    }
            //}
            //catch (Exception ex)
            //{
            //    //handle error logging
            //}
        }
    }
}
