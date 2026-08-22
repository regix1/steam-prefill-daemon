using Moq;
using Spectre.Console.Testing;
using SteamKit2;
using SteamPrefill.Handlers;
using SteamPrefill.Handlers.Steam;
using SteamPrefill.Models;
using SteamPrefill.Models.Enums;
using Xunit;
using OperatingSystem = SteamPrefill.Models.Enums.OperatingSystem;

namespace SteamPrefill.Test
{
    [Collection("SteamAccountFile")]
    public sealed class DepotHandlerTests
    {
        private readonly DepotHandler _depotHandler;
        private readonly Mock<AppInfoHandler> _appInfoHandlerMock;

        public DepotHandlerTests()
        {
            Steam3Session steam3 = new Steam3Session(null);
            // User will always have access to every depot
            steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(123);
            // User will always have access to this app
            steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);

            // Setting up a "valid" app info object
            var appKeyValues = new KeyValue
            {
                Children =
                {
                    new KeyValue("common")
                    {
                        Children = { new KeyValue("type", "game") }
                    }
                }
            };
            _appInfoHandlerMock = new Mock<AppInfoHandler>(null, null, null);
            _appInfoHandlerMock.Setup(e => e.GetAppInfoAsync(
                                   It.IsAny<uint>(),
                                   It.IsAny<CancellationToken>()))
                               .Returns(Task.FromResult(new AppInfo(steam3, 222, appKeyValues)));

            _depotHandler = new DepotHandler(new TestConsole(), steam3, _appInfoHandlerMock.Object, null);
        }

        [Fact]
        public async Task UserDoesNotHaveDepotAccess_DepotIsFiltered()
        {
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 777, ManifestId = 55 }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments(), depotList);
            // Since the user has no access to any depots, we should expect this result to be empty
            Assert.Empty(filteredDepots);
        }

        [Fact]
        public async Task DepotHasNoMetadata_DepotIsIncluded()
        {
            var depotList = new List<DepotInfo>
            {
                // Depot is being setup without metadata
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555 }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments(), depotList);
            // Since the depot has no metadata, it should always be included
            Assert.Single(filteredDepots);
        }

        [Fact]
        public async Task OperatingSystemDoesntMatch_DepotIsNotIncluded()
        {
            // Depot is for macos only
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222)
                {
                    DepotId = 123,
                    ManifestId = 5555,
                    SupportedOperatingSystems = new List<OperatingSystem> { OperatingSystem.MacOS }
                }
            };

            var downloadArguments = new DownloadArguments { OperatingSystems = new List<OperatingSystem> { OperatingSystem.Windows } };
            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(downloadArguments, depotList);

            // We are only interested in windows depots, so we should expect the depot to be filtered
            Assert.Empty(filteredDepots);
        }

        [Theory]
        [InlineData("windows", "windows")]
        [InlineData("windows linux", "linux")]
        [InlineData("linux", "windows linux")]
        public async Task OperatingSystemMatches_DepotIsIncluded(string supportedOS, string downloadOS)
        {
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222)
                {
                    DepotId = 123,
                    ManifestId = 5555,
                    SupportedOperatingSystems = supportedOS.Split(" ").Select(e => OperatingSystem.FromValue(e)).ToList()
                }
            };

            var downloadArguments = new DownloadArguments
            {
                OperatingSystems = downloadOS.Split(" ").Select(e => OperatingSystem.FromValue(e)).ToList()
            };
            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(downloadArguments, depotList);
            Assert.Single(filteredDepots);
        }


        [Fact]
        public async Task ArchitectureDoesntMatch_DepotIsNotIncluded()
        {
            // Depot is for 64 bit only
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555, Architecture = Architecture.x64 }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments { Architecture = Architecture.x86 }, depotList);
            // We are only interested in 32 bit depots, so we should expect the depot to be filtered
            Assert.Empty(filteredDepots);
        }

        [Fact]
        public async Task ArchitectureMatches_DepotIsIncluded()
        {
            // Depot is for 64 bit only
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555, Architecture = Architecture.x64 }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments { Architecture = Architecture.x64 }, depotList);
            // Since we want 64 bit depots, then we should expect the depot to be included
            Assert.Single(filteredDepots);
        }

        [Fact]
        public async Task LanguageDoesntMatch_DepotIsNotIncluded()
        {
            // Depot is for spanish
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555, Languages = new List<Language> { Language.Spanish } }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments { Language = Language.English }, depotList);
            // We are only interested in english depots, so we should expect the depot to be filtered
            Assert.Empty(filteredDepots);
        }

        [Fact]
        public async Task LanguageMatches_DepotIsIncluded()
        {
            // Depot is for english
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555, Languages = new List<Language> { Language.English } }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments { Language = Language.English }, depotList);
            // Since we want english depots, then we should expect the depot to be included
            Assert.Single(filteredDepots);
        }

        [Fact]
        public async Task LowViolenceDepots_AreFiltered()
        {
            var depotList = new List<DepotInfo>
            {
                new DepotInfo(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555, LowViolence = true }
            };

            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(new DownloadArguments(), depotList);
            // Low violence depots should be expected to be filtered.
            Assert.Empty(filteredDepots);
        }

        [Fact]
        public async Task FilteringDepots_PropagatesCallerCancellation()
        {
            var requestStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _appInfoHandlerMock.Setup(e => e.GetAppInfoAsync(
                                   It.IsAny<uint>(),
                                   It.IsAny<CancellationToken>()))
                               .Returns(async (uint _, CancellationToken token) =>
                               {
                                   requestStarted.TrySetResult();
                                   await Task.Delay(Timeout.InfiniteTimeSpan, token);
                                   throw new InvalidOperationException("The cancelled app-info request unexpectedly resumed.");
                               });
            using var cancellation = new CancellationTokenSource();

            var filterTask = _depotHandler.FilterDepotsToDownloadAsync(
                new DownloadArguments(),
                new List<DepotInfo>
                {
                    new(new KeyValue("0"), 222) { DepotId = 123, ManifestId = 5555 }
                },
                cancellation.Token);
            await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => filterTask);
        }

        [Fact]
        public void EmptyDepotList_ReportsUpToDate()
        {
            // All() over an empty list is true, so a list that emptied out while fetching manifests reports the app
            // as up to date with nothing to download.  Every caller has to check for an empty list before trusting this.
            Assert.True(_depotHandler.AppIsUpToDate(new List<DepotInfo>()));
        }

        [Fact]
        public void ManifestlessSelfLinkedDepot_IsInvalid()
        {
            var depotKey = new KeyValue("123")
            {
                Children = { new KeyValue("depotfromapp", "123") }
            };

            Assert.True(new DepotInfo(depotKey, 222).IsInvalidDepot);
        }

        [Fact]
        public void ExplicitlyEmptyPublicManifest_IsInvalid()
        {
            var depotKey = new KeyValue("1770480")
            {
                Children =
                {
                    new KeyValue("dlcappid", "1770480"),
                    new KeyValue("manifests")
                    {
                        Children =
                        {
                            new KeyValue("public")
                            {
                                Children =
                                {
                                    new KeyValue("gid", "2836902461265788005"),
                                    new KeyValue("size", "0"),
                                    new KeyValue("download", "0")
                                }
                            }
                        }
                    }
                }
            };

            Assert.True(new DepotInfo(depotKey, 1770480).IsInvalidDepot);
        }

        [Fact]
        public void VtolDlcDepot_UsesDlcAppForManifestAndLicense()
        {
            var depotKey = new KeyValue("1770480")
            {
                Children =
                {
                    new KeyValue("dlcappid", "1770480"),
                    new KeyValue("manifests")
                    {
                        Children = { new KeyValue("public", "2836902461265788005") }
                    }
                }
            };
            var depot = new DepotInfo(depotKey, 1770480);
            depot.AttachToParentApp(667970, 1770480);

            Assert.False(depot.IsInvalidDepot);
            Assert.Equal(1770480U, depot.SourceAppId);
            Assert.Equal(1770480U, depot.ManifestRequestAppId);
            Assert.Equal(1770480U, depot.LicenseAppId);
            Assert.Equal(667970U, depot.ParentAppId);
            Assert.DoesNotContain(1770480UL, ExcludedDepots.Ids);
        }

        [Fact]
        public async Task DlcDepotWithSelfLinkedDepotFromApp_IsAttachedToTheBaseGame()
        {
            var steam3 = new Steam3Session(null);
            steam3.LicenseManager._userLicenses.OwnedAppIds.Add(1770480);
            var baseGameKeyValues = new KeyValue
            {
                Children =
                {
                    new KeyValue("common")
                    {
                        Children =
                        {
                            new KeyValue("type", "game"),
                            new KeyValue("listofdlc", "1770480")
                        }
                    }
                }
            };
            var dlcKeyValues = new KeyValue
            {
                Children =
                {
                    new KeyValue("common") { Children = { new KeyValue("type", "dlc") } },
                    new KeyValue("depots")
                    {
                        Children =
                        {
                            new KeyValue("1770480")
                            {
                                Children =
                                {
                                    new KeyValue("depotfromapp", "1770480"),
                                    new KeyValue("dlcappid", "1770480"),
                                    new KeyValue("manifests")
                                    {
                                        Children = { new KeyValue("public", "2836902461265788005") }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            var appInfoHandler = new AppInfoHandler(new TestConsole(), steam3, steam3.LicenseManager);
            var baseGame = new AppInfo(steam3, 667970, baseGameKeyValues);
            appInfoHandler.LoadedAppInfos.TryAdd(667970, baseGame);
            appInfoHandler.LoadedAppInfos.TryAdd(1770480, new AppInfo(steam3, 1770480, dlcKeyValues));

            await appInfoHandler.FetchDlcAppInfoAsync(CancellationToken.None);

            var attachedDepot = Assert.Single(baseGame.Depots);
            Assert.Equal(1770480u, attachedDepot.ManifestRequestAppId);
            Assert.Equal(1770480u, attachedDepot.LicenseAppId);
        }

        [Fact]
        public async Task DlcDepotFromSteamMetadata_IsAttachedToTheBaseGame()
        {
            var steam3 = new Steam3Session(null);
            steam3.LicenseManager._userLicenses.OwnedAppIds.Add(1770480);
            var baseGameKeyValues = new KeyValue
            {
                Children =
                {
                    new KeyValue("common") { Children = { new KeyValue("type", "game") } },
                    new KeyValue("extended") { Children = { new KeyValue("listofdlc", "1770480") } }
                }
            };
            var dlcKeyValues = new KeyValue
            {
                Children =
                {
                    new KeyValue("common") { Children = { new KeyValue("type", "dlc") } },
                    new KeyValue("depots")
                    {
                        Children =
                        {
                            new KeyValue("1770480")
                            {
                                Children =
                                {
                                    new KeyValue("dlcappid", "1770480"),
                                    new KeyValue("manifests")
                                    {
                                        Children = { new KeyValue("public", "2836902461265788005") }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            var appInfoHandler = new AppInfoHandler(new TestConsole(), steam3, steam3.LicenseManager);
            var baseGame = new AppInfo(steam3, 667970, baseGameKeyValues);
            appInfoHandler.LoadedAppInfos.TryAdd(667970, baseGame);
            appInfoHandler.LoadedAppInfos.TryAdd(1770480, new AppInfo(steam3, 1770480, dlcKeyValues));

            await appInfoHandler.FetchDlcAppInfoAsync(CancellationToken.None);

            // The base game is found through the DLC list, none of these ids are handed to the depot by the test
            var attachedDepot = Assert.Single(baseGame.Depots);
            Assert.Equal(1770480U, attachedDepot.DepotId);
            Assert.Equal(1770480U, attachedDepot.SourceAppId);
            Assert.Equal(1770480U, attachedDepot.ManifestRequestAppId);
            Assert.Equal(1770480U, attachedDepot.LicenseAppId);
        }

        [Fact]
        public void SharedDlcDepot_UsesLinkedAppForManifestAndDlcAppForLicense()
        {
            var depotKey = new KeyValue("123")
            {
                Children =
                {
                    new KeyValue("depotfromapp", "333"),
                    new KeyValue("dlcappid", "444")
                }
            };
            var depot = new DepotInfo(depotKey, 222) { ManifestId = 555 };

            Assert.Equal(333U, depot.ManifestRequestAppId);
            Assert.Equal(444U, depot.LicenseAppId);
        }

        [Fact]
        public async Task UserDoesNotOwnDlcApp_DepotIsFiltered()
        {
            var depotKey = new KeyValue("123")
            {
                Children = { new KeyValue("dlcappid", "444") }
            };
            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(
                new DownloadArguments(),
                new List<DepotInfo> { new DepotInfo(depotKey, 222) { ManifestId = 5555 } });

            Assert.Empty(filteredDepots);
        }

        [Fact]
        public async Task LinkedDepotWithoutMatchingManifest_IsRemovedWithoutDroppingValidDepots()
        {
            var depotKey = new KeyValue("123")
            {
                Children = { new KeyValue("depotfromapp", "333") }
            };
            var validDepot = new DepotInfo(new KeyValue("0"), 222) { DepotId = 456, ManifestId = 789 };
            var depots = new List<DepotInfo> { validDepot, new DepotInfo(depotKey, 222) };

            await _depotHandler.BuildLinkedDepotInfoAsync(depots);

            Assert.Single(depots);
            Assert.Same(validDepot, depots[0]);
        }
    }
}
