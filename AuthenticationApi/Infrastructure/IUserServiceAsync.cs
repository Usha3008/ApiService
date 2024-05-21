using AuthenticationApi.DataAccess;
using AuthenticationClassLibrary;
using AuthenticationClassLibrary.Models;
using Microsoft.Data.SqlClient;
using System.Data;

namespace AuthenticationApi.Infrastructure
{
    public interface IUserServiceAsync
    {
        Task<User> AuthenticateAsync(AuthenticationRequest model);
        Task<User> GetUserDetails(int userId);

        Task<bool> UpdatePassword(string username, string newPassword);
    }

    public class UserService : BaseDataAccess, IUserServiceAsync
    {
        public UserService(IConfiguration config) : base(config)
        {

        }

        public async Task<User?> AuthenticateAsync(AuthenticationRequest model)
        {
            User? user = null;
            var parameters = new[]
            {
        new SqlParameter("@inputUsername", model.Username),
        new SqlParameter("@inputPassword", model.Password)
    };

            using (var reader = ExecuteReader("sp_GetUserByUsernameAndPassword", CommandType.StoredProcedure, parameters))
            {
                if (reader.HasRows)
                {
                    await reader.ReadAsync();
                    var userId = reader.GetInt32(0);
                    var username = reader.GetString(1);
                    var password = reader.GetString(2);
                    var lastPasswordChange = reader.IsDBNull(3) ? null : (DateTime?)reader.GetDateTime(3);
                    var isActive = reader.GetBoolean(4);
                    var roleId = reader.GetInt32(5);

                    // Assess whether the last_password_change is null
                    bool mustChangePassword = !lastPasswordChange.HasValue;

                    user = new User
                    {
                        UserId = userId,
                        UserName = username,
                        Password = password,
                        Last_Password_Change = lastPasswordChange,
                        isActive = isActive,
                        RoleID = roleId,
                        MustChangePassword = mustChangePassword // Set this property
                    };
                }
            }
            return user;
        }
        //public async Task<User?> AuthenticateAsync(AuthenticationRequest model)
        //{
        //    User? user = null;
        //    var parameters = new[]
        //    {
        //        new SqlParameter("@inputUsername", model.Username),
        //        new SqlParameter("@inputPassword", model.Password)
        //    };

        //    using (var reader = ExecuteReader("sp_GetUserByUsernameAndPassword", CommandType.StoredProcedure, parameters))
        //    {
        //        if (reader.HasRows)
        //        {
        //            // Read user details
        //            await reader.ReadAsync();
        //            var userId = reader.GetInt32(0);
        //            var username = reader.GetString(1);
        //            var password = reader.GetString(2);
        //            var lastPasswordChange = reader.IsDBNull(3) ? null : (DateTime?)reader.GetDateTime(3);
        //            var isActive = reader.GetBoolean(4);

        //            var roleId = reader.GetInt32(5);
        //            // Create and return the User object
        //            user = new User
        //            {
        //                UserId = userId,
        //                UserName = username,
        //                Password = password,
        //                Last_Password_Change = lastPasswordChange,
        //                isActive = isActive,
        //                RoleID = roleId
        //            };
        //        }
        //    }
        //    return user;
        //}

        public async Task<User> GetUserDetails(int userId)
        {
            User user = null;

            var parameters = new[]
            {
                new SqlParameter("@inputUserId", userId)
            };

            using (var reader = ExecuteReader("sp_GetUserDetailsById", CommandType.StoredProcedure, parameters))
            {
                if (reader.HasRows)
                {
                    await reader.ReadAsync(); // Read the first row asynchronously
                    var username = reader.GetString(1);
                    var password = reader.GetString(2);
                    var lastPasswordChange = reader.IsDBNull(3) ? null : (DateTime?)reader.GetDateTime(3);
                    var isActive = reader.GetBoolean(4);

                    var roleId = reader.GetInt32(5);

                    // Create the User object
                    user = new User
                    {
                        UserId = userId,
                        UserName = username,
                        Password = password,
                        Last_Password_Change = lastPasswordChange,
                        isActive = isActive,

                        RoleID = roleId
                    };
                }
            }
            return user;
        }

        public async Task<bool> UpdatePassword(string username, string newPassword)
        {
            try
            {
                var parameters = new[]
                {
            new SqlParameter("@Username", username),
            new SqlParameter("@NewPassword", newPassword)
        };

                await Task.Run(() => ExecuteNonQuery("sp_UpdateUserPassword", CommandType.StoredProcedure, parameters));
                return true;
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error updating password: {ex.Message}");
                return false;
            }
        }

    }
}