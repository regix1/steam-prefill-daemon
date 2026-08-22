namespace SteamPrefill.Models
{
    public sealed class DepotInfo
    {
        public uint DepotId { get; init; }
        public string Name { get; }

        public ulong? ManifestId { get; set; }
        public bool HasExplicitlyEmptyPublicManifest { get; }

        public string ManifestFileName => $"{AppConfig.TempDir}/{SourceAppId}_{ManifestRequestAppId}_{DepotId}_{ManifestId}.bin";

        /// <summary>
        /// The app whose PICS record contained this depot.
        /// </summary>
        public uint SourceAppId { get; private set; }

        /// <summary>
        /// AppID Steam expects when requesting metadata and manifest authorization.
        /// This is the app whose PICS record supplied the depot unless depotfromapp points to another usable app.
        /// </summary>
        public uint ManifestRequestAppId
        {
            get
            {
                if (DepotFromApp is uint fromApp && fromApp != DepotId && fromApp != DlcAppId)
                {
                    return fromApp;
                }
                return SourceAppId;
                }
            }

        /// <summary>
        /// App the account must own to access this depot.
        /// </summary>
        public uint LicenseAppId => DlcAppId ?? ManifestRequestAppId;

        /// <summary>
        /// Determines if a depot is a "linked" depot.  If the current depot is linked, it won't actually have a manifest to download under the current app.
        /// Instead, the depot will need to be downloaded from the linked app.
        /// </summary>
        public uint? DepotFromApp { get; }
        public uint? DlcAppId { get; private set; }
        public uint? ParentAppId { get; private set; }

        // If there is no manifest we can't download this depot, and if there is no valid shared depot then
        // we can't look up a related manifest we could use. Some DLC depots incorrectly link to themselves.
        public bool IsInvalidDepot =>
            HasExplicitlyEmptyPublicManifest ||
            (ManifestId == null && (DepotFromApp == null || DepotFromApp.Value == DepotId));

        public List<OperatingSystem> SupportedOperatingSystems { get; init; } = new List<OperatingSystem>();
        public Architecture Architecture { get; init; }
        public List<Language> Languages { get; init; }
        public bool? LowViolence { get; init; }

        public DepotInfo(KeyValue rootKey, uint appId)
        {
            DepotId = uint.Parse(rootKey.Name);
            Name = rootKey["name"].Value;
            SourceAppId = appId;

            var publicManifest = rootKey["manifests"]["public"];
            ManifestId = publicManifest["gid"].AsUnsignedLongNullable();
            // Legacy key where the manifest id was previously stored.  Not all depots have migrated to the new "gid" key, so this is still necessary.
            if (ManifestId == null)
            {
                ManifestId = publicManifest.AsUnsignedLongNullable();
            }
            var manifestSize = publicManifest["size"].AsUnsignedLongNullable();
            var manifestDownloadSize = publicManifest["download"].AsUnsignedLongNullable();
            HasExplicitlyEmptyPublicManifest =
                ManifestId.HasValue &&
                manifestSize == 0 &&
                manifestDownloadSize == 0;

            DepotFromApp = rootKey["depotfromapp"].AsUnsignedIntNullable();
            DlcAppId = rootKey["dlcappid"].AsUnsignedIntNullable();

            // Config Section
            if (rootKey["config"]["oslist"] != KeyValue.Invalid)
            {
                SupportedOperatingSystems = rootKey["config"]["oslist"].Value
                                                                       .Split(',')
                                                                       .Select(e => OperatingSystem.FromValue(e))
                                                                       .ToList();
            }

            Architecture.TryFromValue(rootKey["config"]["osarch"].ToLowerCaseString(), out var appType);
            Architecture = appType;

            Languages = rootKey["config"]["language"].SplitCommaDelimited()
                                                    .Select(e => Language.FromValue(e))
                                                    .ToList();

            if (rootKey["config"]["lowviolence"].Value is "1")
            {
                LowViolence = true;
            }
        }

        /// <summary>
        /// Attaches a DLC depot to the game being processed without changing its Steam manifest context.
        /// The DLC source AppID remains both the manifest request context and entitlement check.
        /// </summary>
        public void AttachToParentApp(uint parentAppId, uint dlcAppId)
        {
            ParentAppId = parentAppId;
            DlcAppId ??= dlcAppId;
        }

        public override string ToString()
        {
            return $"{DepotId} - {Name}";
        }
    }
}