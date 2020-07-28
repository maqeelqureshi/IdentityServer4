using DAL.Core;
using Entities;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using WebApi.Services;


namespace Host.Configuration.Custom
{
    public class TokenStore : IPersistedGrantStore
    {
        IUnitOfWork uow;
        public TokenStore(IUnitOfWork unitofWork)
        {
            this.uow = unitofWork;
        }

        public Task<IEnumerable<PersistedGrant>> GetAllAsync(string subjectId)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                IEnumerable<PersistedGrant> pg = ss.PersistedGrantStore_GetAllAsync(subjectId).Select(x => new PersistedGrant()
                {
                    Key = x.Key,
                    SubjectId = x.SubjectId,
                    ClientId = x.ClientId,
                    CreationTime = x.CreationTime,
                    Data = x.Data,
                    Expiration = x.Expiration,
                    Type = x.Type
                }).ToList();

                return Task.FromResult(pg);
            }
        }

        public Task<PersistedGrant> GetAsync(string key)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                IEnumerable<PersistedGrant> pg = ss.PersistedGrantStore_GetAsync(key).Select(x => new PersistedGrant()
                {
                    Key = x.Key,
                    SubjectId = x.SubjectId,
                    ClientId = x.ClientId,
                    CreationTime = x.CreationTime,
                    Data = x.Data,
                    Expiration = x.Expiration,
                    Type = x.Type
                }).ToList();

                return Task.FromResult(pg.FirstOrDefault());
            }
        }

        public Task RemoveAllAsync(string subjectId, string clientId)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                var rslt = ss.PersistedGrantStore_RemoveAllAsync(subjectId, clientId, "");
                if (rslt.ErrorCode == -1)
                    return Task.FromResult(0);
                else
                {
                    throw new Exception("ErrorRemovingUser");
                }
            }
        }

        public Task RemoveAllAsync(string subjectId, string clientId, string type)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                var rslt = ss.PersistedGrantStore_RemoveAllAsync(subjectId, clientId, "");
                if (rslt.ErrorCode == -1)
                    return Task.FromResult(0);
                else
                {
                    throw new Exception("ErrorRemovingUser");
                }
            }
        }

        public Task RemoveAsync(string key)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                var rslt = ss.PersistedGrantStore_RemoveAsync(key);
                return Task.FromResult(0);
            }
        }

        public Task StoreAsync(PersistedGrant grant)
        {
            using (SecurityService ss = new SecurityService(uow))
            {
                ss.PersistedGrantStore_Insert(new Entities.UserPersistantGrant()
                {
                    Key = grant.Key,
                    SubjectId = grant.SubjectId,
                    ClientId = grant.ClientId,
                    CreationTime = grant.CreationTime,
                    Data = grant.Data,
                    Expiration = grant.Expiration,
                    Type = grant.Type
                });
            }

            return Task.FromResult(0);
        }
    }

    //public interface ICustomUserStore<TUser>
    //{
    //    //
    //    // Summary:
    //    //     Creates the specified user in the user store.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user to create.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the Microsoft.AspNetCore.Identity.IdentityResult of the creation operation.
    //    Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Deletes the specified user from the user store.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user to delete.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the Microsoft.AspNetCore.Identity.IdentityResult of the update operation.
    //    Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Finds and returns a user, if any, who has the specified userId.
    //    //
    //    // Parameters:
    //    //   userId:
    //    //     The user ID to search for.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the user matching the specified userId if it exists.
    //    Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Finds and returns a user, if any, who has the specified normalized user name.
    //    //
    //    // Parameters:
    //    //   normalizedUserName:
    //    //     The normalized user name to search for.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the user matching the specified normalizedUserName if it exists.
    //    Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Gets the normalized user name for the specified user.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user whose normalized name should be retrieved.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the normalized user name for the specified user.
    //    Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Gets the user identifier for the specified user.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user whose identifier should be retrieved.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the identifier for the specified user.
    //    Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Gets the user name for the specified user.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user whose name should be retrieved.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the name for the specified user.
    //    Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Sets the given normalized name for the specified user.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user whose name should be set.
    //    //
    //    //   normalizedName:
    //    //     The normalized name to set.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation.
    //    Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Sets the given userName for the specified user.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user whose name should be set.
    //    //
    //    //   userName:
    //    //     The user name to set.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation.
    //    Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken);
    //    //
    //    // Summary:
    //    //     Updates the specified user in the user store.
    //    //
    //    // Parameters:
    //    //   user:
    //    //     The user to update.
    //    //
    //    //   cancellationToken:
    //    //     The System.Threading.CancellationToken used to propagate notifications that the
    //    //     operation should be canceled.
    //    //
    //    // Returns:
    //    //     The System.Threading.Tasks.Task that represents the asynchronous operation, containing
    //    //     the Microsoft.AspNetCore.Identity.IdentityResult of the update operation.
    //    Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken);


    //    //
    //    // Summary:
    //    //     Automatically provisions a user.
    //    //
    //    // Parameters:
    //    //   provider:
    //    //     The provider.
    //    //
    //    //   userId:
    //    //     The user identifier.
    //    //
    //    //   claims:
    //    //     The claims.
    //    TUser AutoProvisionUser(string provider, string userId, List<Claim> claims);
    //    //
    //    // Summary:
    //    //     Finds the user by external provider.
    //    //
    //    // Parameters:
    //    //   provider:
    //    //     The provider.
    //    //
    //    //   userId:
    //    //     The user identifier.
    //    TUser FindByExternalProvider(string provider, string userId);
    //    //
    //    // Summary:
    //    //     Finds the user by subject identifier.
    //    //
    //    // Parameters:
    //    //   subjectId:
    //    //     The subject identifier.
    //    TUser FindBySubjectId(string subjectId);
    //    //
    //    // Summary:
    //    //     Finds the user by username.
    //    //
    //    // Parameters:
    //    //   username:
    //    //     The username.
    //    TUser FindByUsername(string username);
    //    //
    //    // Summary:
    //    //     Validates the credentials.
    //    //
    //    // Parameters:
    //    //   username:
    //    //     The username.
    //    //
    //    //   password:
    //    //     The password.
    //    bool ValidateCredentials(string username, string password);
    //}
    //public class UserStore : ICustomUserStore<Entities.User>
    //{
    //    IUnitOfWork uow;
    //    public UserStore(IUnitOfWork unitofWork)
    //    {
    //        this.uow = unitofWork;
    //    }

    //    public User AutoProvisionUser(string provider, string userId, List<Claim> claims)
    //    {
    //        UsersService ss = new UsersService(uow);

    //        User u = new User();
    //        u.Name = claims.Where(x => x.Type == ClaimTypes.Name).FirstOrDefault().Value;
    //        u.Email = claims.Where(x => x.Type == ClaimTypes.Email).FirstOrDefault().Value;
    //        return ss.SignupExternalUser(u).Result;
    //    }

    //    public Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public User FindByExternalProvider(string provider, string username)
    //    {
    //        using (SecurityService ss = new SecurityService(uow))
    //        {
    //            return ss.FindByUsername(username).Result;
    //        }
    //        // throw new NotImplementedException();
    //    }

    //    public Task<User> FindByIdAsync(string userId, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task<User> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public User FindBySubjectId(string subjectId)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public User FindByUsername(string username)
    //    {
    //        using (SecurityService ss = new SecurityService(uow))
    //        {
    //            return ss.FindByUsername(username).Result;
    //        }
    //    }

    //    public Task<string> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task<string> GetUserNameAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task SetNormalizedUserNameAsync(User user, string normalizedName, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task SetUserNameAsync(User user, string userName, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public bool ValidateCredentials(string username, string password)
    //    {
    //        using (SecurityService ss = new SecurityService(uow))
    //        {
    //            if (ss.ValidateUser(username, password).ErrorCode == -1)
    //                return true;
    //            else
    //                return false;
    //        }
    //    }
    //}
}
