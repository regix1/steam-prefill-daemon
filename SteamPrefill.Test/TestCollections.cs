using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// DepotHandlerTests, TokenStorageEncryptionTests, and LogoutMidLoginShutdownTests all construct a
    /// Steam3Session (directly or via SteamPrefillApi.InitializeAsync), which reads/writes the shared
    /// on-disk account store file. xunit runs different test classes in parallel by default, and two of
    /// them opening that file at the same time throws IOException ("used by another process"). Forcing
    /// them into one non-parallel collection avoids the race.
    /// </summary>
    [CollectionDefinition("SteamAccountFile", DisableParallelization = true)]
    public sealed class SteamAccountFileCollection
    {
    }
}
