using System.IdentityModel.Tokens.Jwt;
using SteamPrefill.Api;

namespace SteamPrefill.Settings
{
    /// <summary>
    /// Keeps track of the auth tokens (JWT) returned by Steam, that allow for subsequent logins without passwords.
    /// </summary>
    [ProtoContract(SkipConstructor = true)]
    public sealed class UserAccountStore
    {
        [ProtoMember(3)]
        public string CurrentUsername { get; set; }

        /// <summary>
        /// Used to identify separate instances of Steam/SteamPrefill on the Steam network.
        /// As long as these don't collide, multiple instances can be logged in without logging each other out.
        /// </summary>
        [ProtoMember(4)]
        public uint? SessionId { get; private set; }

        /// <summary>
        /// Steam has switched over to using JWT tokens for authorization.
        /// </summary>
        [ProtoMember(5)]
        public string AccessToken { get; set; }

        /// <summary>
        /// Optional auth provider for API/daemon mode (bypasses console prompts)
        /// </summary>
        [ProtoIgnore]
        public ISteamAuthProvider? AuthProvider { get; set; }

        [SuppressMessage("Security", "CA5394:Random is an insecure RNG", Justification = "Security doesn't matter here, as all that is needed is a unique id.")]
        private UserAccountStore()
        {
            var random = new Random();
            SessionId = (uint)random.Next(0, 16384);
        }

        /// <summary>
        /// Gets the current user's username, if they have already entered it before.
        /// If they have not yet entered it, they will be prompted to do so.
        ///
        /// Will timeout after 30 seconds of no user activity.
        /// </summary>
        public async Task<string> GetUsernameAsync(IAnsiConsole ansiConsole)
        {
            if (!string.IsNullOrEmpty(CurrentUsername))
            {
                return CurrentUsername;
            }

            // Use auth provider if available (API/daemon mode)
            if (AuthProvider != null)
            {
                CurrentUsername = await AuthProvider.GetUsernameAsync();
                return CurrentUsername;
            }

            CurrentUsername = await PromptForUsernameAsync(ansiConsole).WaitAsync(TimeSpan.FromSeconds(30));
            return CurrentUsername;
        }

        /// <summary>
        /// Gets password using auth provider if available, otherwise uses console prompt
        /// </summary>
        public async Task<string?> GetPasswordAsync(IAnsiConsole ansiConsole, string? promptText = null)
        {
            // Use auth provider if available (API/daemon mode)
            if (AuthProvider != null)
            {
                if (AccessTokenIsValid())
                {
                    return await AuthProvider.GetCachedPasswordAsync();
                }
                return await AuthProvider.GetPasswordAsync();
            }

            // Fall back to console prompt
            return await ansiConsole.ReadPasswordAsync(promptText);
        }

        public bool AccessTokenIsValid()
        {
            if (string.IsNullOrEmpty(AccessToken))
            {
                return false;
            }

            var parsedToken = new JwtSecurityToken(AccessToken);

            // Tokens seem to be valid for ~6 months.  We're going to add a bit of "buffer" (1 day) to make sure that new tokens are request prior to expiration
            var tokenHasExpired = DateTimeOffset.Now.DateTime.AddDays(1) < parsedToken.ValidTo;
            return tokenHasExpired;
        }

        private async Task<string> PromptForUsernameAsync(IAnsiConsole ansiConsole)
        {
            return await Task.Run(() =>
            {
                ansiConsole.MarkupLine($"A {Cyan("Steam")} account is required in order to prefill apps!");

                var prompt = new TextPrompt<string>($"Please enter your {Cyan("Steam account name")} : ")
                {
                    PromptStyle = new Style(SpectreColors.MediumPurple1)
                };
                return ansiConsole.Prompt(prompt);
            });
        }

        /// <summary>
        /// Sets credentials from a refresh token (for auto-login)
        /// </summary>
        public void SetCredentialsFromToken(string username, string refreshToken)
        {
            CurrentUsername = username;
            AccessToken = refreshToken;
            Save();
        }

        #region Serialization

        [SuppressMessage("Security", "CA5394:Random is an insecure RNG", Justification = "Security doesn't matter here, as all that is needed is a unique id.")]
        public static UserAccountStore LoadFromFile()
        {
            if (!File.Exists(AppConfig.AccountSettingsStorePath))
            {
                return new UserAccountStore();
            }

            using var fileStream = File.Open(AppConfig.AccountSettingsStorePath, FileMode.Open, FileAccess.Read);
            var userAccountStore = ProtoBuf.Serializer.Deserialize<UserAccountStore>(fileStream);

            // Ensure SessionId is set - protobuf skips constructor so old files may not have it
            // This prevents LoginID collisions with lancache-manager depot mapping (which uses 16384-65535)
            if (userAccountStore.SessionId == null)
            {
                var random = new Random();
                userAccountStore.SessionId = (uint)random.Next(0, 16384);
                userAccountStore.Save(); // Persist so it stays consistent
            }

            return userAccountStore;
        }

        public void Save()
        {
            using var fs = File.Open(AppConfig.AccountSettingsStorePath, FileMode.Create, FileAccess.Write);
            ProtoBuf.Serializer.Serialize(fs, this);
        }

        #endregion
    }
}