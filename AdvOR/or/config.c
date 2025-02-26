/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file config.c
 * \brief Code to parse and interpret configuration files.
 **/

#define CONFIG_PRIVATE

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "cpuworker.h"
#include "dirserv.h"
#include "dirvote.h"
#include "dns.h"
#include "geoip.h"
#include "hibernate.h"
#include "main.h"
#include "networkstatus.h"
#include "policies.h"
#include "relay.h"
#include "rendclient.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "seh.h"

#include "procmon.h"

/** Enumeration of types which option values can take */
typedef enum config_type_t {
  CONFIG_TYPE_STRING = 0,   /**< An arbitrary string. */
  CONFIG_TYPE_FILENAME,     /**< A filename: some prefixes get expanded. */
  CONFIG_TYPE_UINT,         /**< A non-negative integer less than MAX_INT */
  CONFIG_TYPE_PORT,         /**< A port from 1...65535, 0 for "not set", or "auto".  */
  CONFIG_TYPE_INTERVAL,     /**< A number of seconds, with optional units*/
  CONFIG_TYPE_MEMUNIT,      /**< A number of bytes, with optional units*/
  CONFIG_TYPE_DOUBLE,       /**< A floating-point value */
  CONFIG_TYPE_BOOL,         /**< A boolean value, expressed as 0 or 1. */
  CONFIG_TYPE_ISOTIME,      /**< An ISO-formated time relative to GMT. */
  CONFIG_TYPE_CSV,          /**< A list of strings, separated by commas and
                              * optional whitespace. */
  CONFIG_TYPE_LINELIST,     /**< Uninterpreted config lines */
  CONFIG_TYPE_LINELIST_S,   /**< Uninterpreted, context-sensitive config lines,
                             * mixed with other keywords. */
  CONFIG_TYPE_LINELIST_V,   /**< Catch-all "virtual" option to summarize
                             * context-sensitive config lines when fetching.
                             */
  CONFIG_TYPE_ROUTERSET,    /**< A list of router names, addrs, and fps,
                             * parsed into a routerset_t. */
  CONFIG_TYPE_OBSOLETE,     /**< Obsolete (ignored) option. */
} config_type_t;

/** An abbreviation for a configuration option allowed on the command line. */
typedef struct config_abbrev_t {
  const char *abbreviated;
  const char *full;
  int commandline_only;
  int warn;
} config_abbrev_t;

/* Handy macro for declaring "In the config file or on the command line,
 * you can abbreviate <b>tok</b>s as <b>tok</b>". */
#define PLURAL(tok) { #tok, #tok "s", 0, 0 }

/** A list of abbreviations and aliases to map command-line options, obsolete
 * option names, or alternative option names, to their current values. */
static config_abbrev_t _option_abbrevs[] = {
  PLURAL(ExitNode),
  PLURAL(EntryNode),
  PLURAL(ExcludeNode),
  PLURAL(FirewallPort),
  PLURAL(LongLivedPort),
  PLURAL(HiddenServiceNode),
  PLURAL(HiddenServiceExcludeNode),
  PLURAL(NumCpu),
  PLURAL(RendNode),
  PLURAL(RendExcludeNode),
  PLURAL(StrictEntryNode),
  PLURAL(StrictExitNode),
  { "l", "Log", 1, 0},
  { "AllowUnverifiedNodes", "AllowInvalidNodes", 0, 0},
  { "AutomapHostSuffixes", "AutomapHostsSuffixes", 0, 0},
  { "AutomapHostOnResolve", "AutomapHostsOnResolve", 0, 0},
  { "BandwidthRateBytes", "BandwidthRate", 0, 0},
  { "BandwidthBurstBytes", "BandwidthBurst", 0, 0},
  { "DirFetchPostPeriod", "StatusFetchPeriod", 0, 0},
  { "MaxConn", "ConnLimit", 0, 1},
  { "ORBindAddress", "ORListenAddress", 0, 0},
  { "DirBindAddress", "DirListenAddress", 0, 0},
  { "SocksBindAddress", "SocksListenAddress", 0, 0},
  { "UseHelperNodes", "UseEntryGuards", 0, 0},
  { "NumHelperNodes", "NumEntryGuards", 0, 0},
  { "UseEntryNodes", "UseEntryGuards", 0, 0},
  { "NumEntryNodes", "NumEntryGuards", 0, 0},
  { "Bridge", "Bridges", 0, 0},
  { "ResolvConf", "ServerDNSResolvConfFile", 0, 1},
  { "SearchDomains", "ServerDNSSearchDomains", 0, 1},
  { "ServerDNSAllowBrokenResolvConf", "ServerDNSAllowBrokenConfig", 0, 0 },
  { "BridgeAuthoritativeDirectory", "BridgeAuthoritativeDir", 0, 0},
  { "HashedControlPassword", "__HashedControlSessionPassword", 1, 0},
  { "ReachableDirAddresses", "ReachableAddresses", 0, 0},
  { "ReachableORAddresses", "ReachableAddresses", 0, 0},
  { "MapAddress", "AddressMap", 0, 0},
  { "NodeFamily", "NodeFamilies", 0, 0},
  { "Start", "AutoStart", 0, 0},
  { NULL, NULL, 0, 0},
};

/** A list of state-file "abbreviations," for compatibility. */
static config_abbrev_t _state_abbrevs[] = {
  { "AccountingBytesReadInterval", "AccountingBytesReadInInterval", 0, 0 },
  { "HelperNode", "EntryGuard", 0, 0 },
  { "HelperNodeDownSince", "EntryGuardDownSince", 0, 0 },
  { "HelperNodeUnlistedSince", "EntryGuardUnlistedSince", 0, 0 },
  { "EntryNode", "EntryGuard", 0, 0 },
  { "EntryNodeDownSince", "EntryGuardDownSince", 0, 0 },
  { "EntryNodeUnlistedSince", "EntryGuardUnlistedSince", 0, 0 },
  { NULL, NULL, 0, 0},
};
#undef PLURAL

/** A variable allowed in the configuration file or on the command line. */
typedef struct config_var_t {
  const char *name; /**< The full keyword (case insensitive). */
  config_type_t type; /**< How to interpret the type and turn it into a
                       * value. */
  off_t var_offset; /**< Offset of the corresponding member of or_options_t. */
  const char *initvalue; /**< String (or null) describing initial value. */
} config_var_t;

/** An entry for config_vars: "The option <b>name</b> has type
 * CONFIG_TYPE_<b>conftype</b>, and corresponds to
 * or_options_t.<b>member</b>"
 */
#define VAR(name,conftype,member,initvalue)                             \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(or_options_t, member), \
      initvalue }
/** As VAR, but the option name and member name are the same. */
#define V(member,conftype,initvalue)                                    \
  VAR(#member, conftype, member, initvalue)
/** An entry for config_vars: "The option <b>name</b> is obsolete." */
#define OBSOLETE(name) { name, CONFIG_TYPE_OBSOLETE, 0, NULL }

/** Array of configuration options.  Until we disallow nonstandard
 * abbreviations, order is significant, since the first matching option will
 * be chosen first.
 */
static config_var_t _option_vars[] = {
  OBSOLETE("AccountingMaxKB"),
  V(AccountingMax,               MEMUNIT,  "0 bytes"),
  V(AccountingStart,             STRING,   NULL),
  V(Address,                     STRING,   NULL),
  V(AllowTorHosts,                UINT,     "2"),
  V(AllowInvalidNodes,           CSV,      "middle,rendezvous"),
  V(AllowNonRFC953Hostnames,     BOOL,     "0"),
  V(AllowSingleHopCircuits,      BOOL,     "0"),
  V(AllowSingleHopExits,         BOOL,     "0"),
  V(AlternateBridgeAuthority,    LINELIST, NULL),
  V(AlternateDirAuthority,       LINELIST, NULL),
  V(AlternateHSAuthority,        LINELIST, NULL),
  V(AssumeReachable,             BOOL,     "0"),
  V(AuthDirBadDir,               LINELIST, NULL),
  V(AuthDirBadExit,              LINELIST, NULL),
  V(AuthDirInvalid,              LINELIST, NULL),
  V(AuthDirFastGuarantee,        MEMUNIT,  "20 KB"),
  V(AuthDirGuardBWGuarantee,     MEMUNIT,  "250 KB"),
  V(AuthDirReject,               LINELIST, NULL),
  V(AuthDirRejectUnlisted,       BOOL,     "0"),
  V(AuthDirListBadDirs,          BOOL,     "0"),
  V(AuthDirListBadExits,         BOOL,     "0"),
  V(AuthDirMaxServersPerAddr,    UINT,     "2"),
  V(AuthDirMaxServersPerAuthAddr,UINT,     "5"),
  VAR("AuthoritativeDirectory",  BOOL, AuthoritativeDir,    "0"),
  V(AutomapHostsOnResolve,       BOOL,     "0"),
  V(AutomapHostsSuffixes,        CSV,      ".onion,.exit"),
  V(AvoidDiskWrites,             BOOL,     "0"),
  V(BandwidthBurst,              MEMUNIT,  "10 MB"),
  V(BandwidthRate,               MEMUNIT,  "5 MB"),
  V(CircuitBandwidthRate,        MEMUNIT,  "0"),
  V(BridgeAuthoritativeDir,      BOOL,     "0"),
  VAR("Bridges",                  LINELIST, Bridges,    NULL),
  V(BridgePassword,              STRING,   NULL),
  V(BridgeRecordUsageByCountry,  BOOL,     "1"),
  V(BridgeRelay,                 BOOL,     "0"),
  V(CellStatistics,              BOOL,     "0"),
  V(LearnCircuitBuildTimeout,    BOOL,     "1"),
  V(CircuitBuildTimeout,         INTERVAL, "1 minute"),
  V(CircuitIdleTimeout,          INTERVAL, "1 hour"),
  V(CircuitStreamTimeout,        INTERVAL, "0"),
  V(CircuitPriorityHalflife,     DOUBLE,  "-100.0"), /*negative:'Use default'*/
  V(ClientDNSRejectInternalAddresses, BOOL,"1"),
  V(ClientRejectInternalAddresses, BOOL,   "1"),
  V(ClientOnly,                  BOOL,     "0"),
  V(ConsensusParams,             STRING,   NULL),
  V(ConnLimit,                   UINT,     "1000"),
  V(ConstrainedSockets,          BOOL,     "0"),
  V(ConstrainedSockSize,         MEMUNIT,  "8192"),
  V(ContactInfo,                 STRING,   NULL),
  V(ControlListenAddress,        LINELIST, NULL),
  V(ControlPort,                 UINT,     "0"),
  V(ControlSocket,               LINELIST, NULL),
  V(CookieAuthentication,        BOOL,     "0"),
  V(CookieAuthFileGroupReadable, BOOL,     "0"),
  V(CookieAuthFile,              STRING,   NULL),
  OBSOLETE("DebugLogFile"),
  V(DirAllowPrivateAddresses,    BOOL,     NULL),
  V(TestingAuthDirTimeToLearnReachability, INTERVAL, "30 minutes"),
  V(DirListenAddress,            LINELIST, NULL),
  OBSOLETE("DirFetchPeriod"),
  V(DirPolicy,                   LINELIST, NULL),
  V(DirPort,                     UINT,     "0"),
  V(DirPortFrontPage,            FILENAME, NULL),
  OBSOLETE("DirPostPeriod"),
  OBSOLETE("DirRecordUsageByCountry"),
  OBSOLETE("DirRecordUsageGranularity"),
  OBSOLETE("DirRecordUsageRetainIPs"),
  OBSOLETE("DirRecordUsageSaveInterval"),
  V(DirReqStatistics,            BOOL,     "1"),
  V(DirServers,                  LINELIST, NULL),
  V(DisableAllSwap,              BOOL,     "0"),
  V(DNSPort,                     PORT,     "0"),
  V(DNSListenAddress,            LINELIST, NULL),
  V(DownloadExtraInfo,           BOOL,     "0"),
  V(EnforceDistinctSubnets,      UINT,     "2"),
  V(EntryNodes,                  ROUTERSET,   NULL),
  V(EntryStatistics,             BOOL,     "0"),
  V(TestingEstimatedDescriptorPropagationTime, INTERVAL, "10 minutes"),
  V(ExcludeNodes,                ROUTERSET, NULL),
  V(ExcludeExitNodes,            ROUTERSET, NULL),
  V(ExcludeSingleHopRelays,      BOOL,     "1"),
  V(ExitNodes,                   ROUTERSET, NULL),
  V(ExitPolicy,                  LINELIST, NULL),
  V(ExitPolicyRejectPrivate,     BOOL,     "0"),
  V(ExitPortStatistics,          BOOL,     "0"),
  V(ExtraInfoStatistics,         BOOL,     "1"),
  V(ExitMaxUptime,		 UINT,	   "21600"),
  V(ExitMaxSeen,		 UINT,	   "15"),
  V(ExitSeenFlags,		 UINT,	   "4"),
  V(FallbackNetworkstatusFile,   FILENAME,  "AdvOR-fallback-consensus"),
  V(FascistFirewall,             BOOL,     "0"),
  V(FirewallPorts,               CSV,      ""),
  V(FastFirstHopPK,              BOOL,     "1"),
  V(FetchDirInfoEarly,           BOOL,     "0"),
  V(FetchDirInfoExtraEarly,      BOOL,     "0"),
  V(FetchServerDescriptors,      BOOL,     "1"),
  V(FetchHidServDescriptors,     BOOL,     "1"),
  V(FetchUselessDescriptors,     BOOL,     "0"),
  V(FetchV2Networkstatus,        BOOL,     "0"),
  V(GiveGuardFlagTo_CVE_2011_2768_VulnerableRelays,BOOL,     "0"),
  OBSOLETE("Group"),
  V(HardwareAccel,               BOOL,     "0"),
  V(HashedControlPassword,       LINELIST, NULL),
  V(HidServDirectoryV2,          BOOL,     "1"),
  VAR("HiddenServiceKey",    LINELIST_S, RendConfigLines,    NULL),
  OBSOLETE("HiddenServiceExcludeNodes"),
  OBSOLETE("HiddenServiceNodes"),
  VAR("HiddenServiceOptions",LINELIST_V, RendConfigLines,    NULL),
  VAR("HiddenServicePort",   LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceVersion",LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceAuthorizeClient",LINELIST_S,RendConfigLines, NULL),
  V(HidServAuth,                 LINELIST, NULL),
  V(HSAuthoritativeDir,          BOOL,     "0"),
  OBSOLETE("HSAuthorityRecordStats"),
  V(DirProxy,                   STRING,   NULL),
  V(DirProxyAuthenticator,      STRING,   NULL),
  V(DirProxyProtocol,             UINT,   "2"),
  V(ORProxy,                  STRING,   NULL),
  V(ORProxyAuthenticator,     STRING,   NULL),
  V(ORProxyProtocol,             UINT,   "1"),
  V(CorporateProxy,                  STRING,   NULL),
  V(CorporateProxyDomain,     STRING,   NULL),
  V(CorporateProxyAuthenticator,     STRING,   NULL),
  V(CorporateProxyProtocol,             UINT,   "0"),
  OBSOLETE("IgnoreVersion"),
  V(KeepalivePeriod,             INTERVAL, "5 minutes"),
  VAR("Log",                     LINELIST, Logs,             NULL),
  OBSOLETE("LinkPadding"),
  OBSOLETE("LogLevel"),
  OBSOLETE("LogFile"),
  V(LongLivedPorts,              CSV,
                         "21,22,706,1863,5050,5190,5222,5223,6667,6697,8300"),
  V(AddressMap,              LINELIST, NULL),
  V(MaxAdvertisedBandwidth,      MEMUNIT,  "1 GB"),
  V(MaxCircuitDirtiness,         INTERVAL, "10 minutes"),
  V(MaxOnionsPending,            UINT,     "100"),
  OBSOLETE("MonthlyAccountingStart"),
  V(MyFamily,                    STRING,   NULL),
  V(NewCircuitPeriod,            INTERVAL, "30 seconds"),
  VAR("NamingAuthoritativeDirectory",BOOL, NamingAuthoritativeDir, "0"),
  V(NatdListenAddress,           LINELIST, NULL),
  V(NatdPort,                    UINT,     "0"),
  V(Nickname,                    STRING,   NULL),
  V(NoPublish,                   BOOL,     "0"),
  V(NodeFamilies,              LINELIST, NULL),
  V(NumCpus,                     UINT,     "1"),
  V(NumEntryGuards,              UINT,     "3"),
  V(ORListenAddress,             LINELIST, NULL),
  V(ORPort,                      PORT,     "0"),
  V(OutboundBindAddress,         STRING,   NULL),
  OBSOLETE("PathlenCoinWeight"),
  V(PerConnBWBurst,              MEMUNIT,  "0"),
  V(PerConnBWRate,               MEMUNIT,  "0"),
  V(PidFile,                     STRING,   NULL),
  V(TestingTorNetwork,           BOOL,     "0"),
  V(ProtocolWarnings,            BOOL,     "0"),
  V(PublishServerDescriptor,     CSV,      "1"),
  V(PublishHidServDescriptors,   BOOL,     "1"),
  V(ReachableAddresses,          LINELIST, NULL),
  V(RecommendedVersions,         LINELIST, NULL),
  V(RecommendedClientVersions,   LINELIST, NULL),
  V(RecommendedServerVersions,   LINELIST, NULL),
  OBSOLETE("RedirectExit"),
  V(RefuseUnknownExits,          STRING,   "auto"),
  V(RejectPlaintextPorts,        CSV,      ""),
  V(RelayBandwidthBurst,         MEMUNIT,  "0"),
  V(RelayBandwidthRate,          MEMUNIT,  "0"),
  OBSOLETE("RendExcludeNodes"),
  OBSOLETE("RendNodes"),
  V(RendPostPeriod,              INTERVAL, "1 hour"),
  V(RephistTrackTime,            INTERVAL, "24 hours"),
  OBSOLETE("RouterFile"),
  V(RunAsDaemon,                 BOOL,     "0"),
//  V(RunTesting,                  BOOL,     "0"),
  OBSOLETE("RunTesting"), // currently unused
  V(SafeLogging,                 BOOL,     "1"),
  V(SafeSocks,                   BOOL,     "0"),
  V(ServerDNSAllowBrokenConfig,  BOOL,     "1"),
  V(ServerDNSAllowNonRFC953Hostnames, BOOL,"0"),
  V(ServerDNSDetectHijacking,    BOOL,     "1"),
  V(ServerDNSRandomizeCase,      BOOL,     "1"),
  V(ServerDNSResolvConfFile,     STRING,   NULL),
  V(ServerDNSSearchDomains,      BOOL,     "0"),
  V(ServerDNSTestAddresses,      CSV,
      "www.google.com,www.mit.edu,www.yahoo.com,www.slashdot.org"),
  V(ShutdownWaitLength,          INTERVAL, "30 seconds"),
  V(SocksListenAddress,          LINELIST, NULL),
  V(SocksPolicy,                 LINELIST, NULL),
  V(SocksPort,                   PORT,     "9050"),
  V(SocksAuthenticator,          STRING,   NULL),
  V(SocksTimeout,                INTERVAL, "2 minutes"),
  OBSOLETE("StatusFetchPeriod"),
  V(StrictEntryNodes,            BOOL,     "0"),
  V(StrictExitNodes,             BOOL,     "0"),
  OBSOLETE("SysLog"),
  V(TestSocks,                   BOOL,     "0"),
  OBSOLETE("TestVia"),
  V(TrackHostExits,              CSV,      NULL),
  V(TrackHostExitsExpire,        INTERVAL, "30 minutes"),
  OBSOLETE("TrafficShaping"),
  V(TransListenAddress,          LINELIST, NULL),
  V(TransPort,                   PORT,     "0"),
  V(TunnelDirConns2,             UINT,     "0"),
  V(UpdateBridgesFromAuthority,  BOOL,     "0"),
  V(UseBridges,                  BOOL,     "0"),
  V(UseEntryGuards,              BOOL,     "1"),
  V(User,                        STRING,   NULL),
  VAR("V1AuthoritativeDirectory",BOOL, V1AuthoritativeDir,   "0"),
  VAR("V2AuthoritativeDirectory",BOOL, V2AuthoritativeDir,   "0"),
  VAR("V3AuthoritativeDirectory",BOOL, V3AuthoritativeDir,   "0"),
  V(TestingV3AuthInitialVotingInterval, INTERVAL, "30 minutes"),
  V(TestingV3AuthInitialVoteDelay, INTERVAL, "5 minutes"),
  V(TestingV3AuthInitialDistDelay, INTERVAL, "5 minutes"),
  V(V3AuthVotingInterval,        INTERVAL, "1 hour"),
  V(V3AuthVoteDelay,             INTERVAL, "5 minutes"),
  V(V3AuthDistDelay,             INTERVAL, "5 minutes"),
  V(V3AuthNIntervalsValid,       UINT,     "3"),
  V(V3AuthUseLegacyKey,          BOOL,     "0"),
  V(V3BandwidthsFile,            FILENAME, NULL),
  VAR("VersioningAuthoritativeDirectory",BOOL,VersioningAuthoritativeDir, "0"),
  V(VirtualAddrNetwork,          STRING,   "127.192.0.0/10"),
  V(WarnPlaintextPorts,          CSV,      "23,109,110,143"),
  VAR("__ReloadTorrcOnSIGHUP",   BOOL,  ReloadTorrcOnSIGHUP,      "1"),
  VAR("__AllDirActionsPrivate",  BOOL,  AllDirActionsPrivate,     "0"),
  VAR("__LeaveStreamsUnattached",BOOL,  LeaveStreamsUnattached,   "0"),
  VAR("__HashedControlSessionPassword", LINELIST, HashedControlSessionPassword,
      NULL),
  V(MaxUnusedOpenCircuits,              UINT,     "14"),
  VAR("__OwningControllerProcess",STRING,OwningControllerProcess, NULL),
  V(MinUptimeHidServDirectoryV2, INTERVAL, "24 hours"),
  V(VoteOnHidServDirectoriesV2,  BOOL,     "1"),
  V(_UsingTestNetworkDefaults,   BOOL,     "0"),
  V(AutoStart,                   UINT,     "0"),
  V(logging,                     UINT,     "16390"),
  V(Logging,                     UINT,     "16390"),
  V(ForceFlags,                  UINT,     "27"),
  V(DirFlags,                    UINT,     "49"),		//1 | 8 | 16 | 32
  V(Confirmations,               UINT,     "13"),	//1 | 4 | 8
  V(IdentityFlags,               UINT,     "1047"),	// IDENTITY_FLAG_EXPIRE_TRACKED_HOSTS | IDENTITY_FLAG_EXPIRE_CIRCUITS | IDENTITY_FLAG_DESTROY_CIRCUITS | IDENTITY_FLAG_LIST_SELECTION | IDENTITY_FLAG_GENERATE_SEEDS | IDENTITY_FLAG_EXPIRE_HTTP_COOKIES | IDENTITY_FLAG_DELETE_HTTP_COOKIES | IDENTITY_FLAG_DELETE_FLASH_COOKIES | IDENTITY_FLAG_CLEAR_FLASH_CACHE | IDENTITY_FLAG_RANDOMIZE_WMPLAYER_ID | IDENTITY_FLAG_REINIT_KEYS
  V(IdentityAutoChange,          INTERVAL, "0"),
  V(HTTPFlags,                   UINT,     "30926"),		// HTTP_SETTING_REFERER_SAME_DOMAIN | HTTP_SETTING_REMOVE_ETAGS | HTTP_SETTING_EXIT_LANGUAGE | HTTP_SETTING_IDENTITY_UA_EXTENSIONS | HTTP_SETTING_REMOVE_IFS | HTTP_SETTING_REMOVE_CLIENT_IP | HTTP_SETTING_REMOVE_UNKNOWN
  V(HTTPAgent,                   UINT,     "0"),		// BROWSER_AUTODETECT
  V(HTTPOS,                      UINT,     "2"),		// BROWSER_OS_WINDOWS
  V(BannedHeaders,               LINELIST, NULL),
  V(RegionalSettings,            UINT,     "256"),	// REGIONAL_SETTINGS_EXIT
  V(winver,                      STRING,   NULL),
  V(torver,                      STRING,   FAKE_TOR_VER),
  V(SelectedTorVer,              STRING,   "<< Auto >>"),
  V(Language,                    STRING,   "< Default >"),
  V(WindowPos,                   STRING,      NULL),
  V(GuiPlacement3,               STRING,      NULL),
  V(GuiType,                     UINT,     "4"),
  V(HotkeyRestore,               UINT,     "2644"),		// Win+Ctrl+VK_T = 0a 54
  V(HotkeyNewIdentity,           UINT,     "2126"),		// Win+VK_N = 08 4E
  V(HotkeyIntercept,             UINT,     "2633"),		// Win+Ctrl+VK_I = 0a 49
  V(HotkeyRelease,               UINT,     "2642"),		// Win+Ctrl+VK_R = 0a 52
  V(HotkeyHideAll,               UINT,     "8384"),		// ` = 20 c0
  V(HotkeyRestoreAll,            UINT,     "6711"),		// Win+Ctrl+7 = 0a 37
  V(LocalHost,                   STRING,   "localhost"),
  V(ResolveTimeout,              UINT,     "300"),
  V(MaxDlFailures,               UINT,     "8"),
  V(MaxFileAge,                  UINT,     "28"),
  V(MaxTimeDelta,                UINT,     "3600"),
  V(BestTimeDelta,               UINT,     "0"),
  V(NotifyFilter,                LINELIST, NULL),
  V(DebugFilter,                 LINELIST, NULL),
  V(BannedHosts,                 LINELIST, NULL),
  V(QuickStart,                  LINELIST, NULL),
  V(SynchronizeExit,             LINELIST, NULL),
  V(Plugins,                     LINELIST, NULL),
  V(PluginOptions,               LINELIST, NULL),
  V(CircuitPathLength,           UINT,     "3"),
  V(NumIntroPoints,              UINT,     "3"),
  V(FavoriteExitNodesPriority,   UINT,     "50"),
  V(IntroCircRetryPeriod,        UINT,     "300"),
  V(MaxCircsPerPeriod,           UINT,     "10"),
  V(MaxRendFailures,             UINT,     "30"),
  V(MaxRendTimeout,              UINT,     "30"),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};

/** Override default values with these if the user sets the TestingTorNetwork
 * option. */
static config_var_t testing_tor_network_defaults[] = {
  V(ServerDNSAllowBrokenConfig,  BOOL,  "1"),
  V(DirAllowPrivateAddresses,    BOOL,     "1"),
  V(EnforceDistinctSubnets,      UINT,     "0"),
  V(AssumeReachable,             BOOL,     "1"),
  V(AuthDirMaxServersPerAddr,    UINT,     "0"),
  V(AuthDirMaxServersPerAuthAddr,UINT,     "0"),
  V(ClientDNSRejectInternalAddresses, BOOL,"0"),
  V(ClientRejectInternalAddresses, BOOL,   "0"),
  V(ExitPolicyRejectPrivate,     BOOL,     "0"),
  V(V3AuthVotingInterval,        INTERVAL, "5 minutes"),
  V(V3AuthVoteDelay,             INTERVAL, "20 seconds"),
  V(V3AuthDistDelay,             INTERVAL, "20 seconds"),
  V(TestingV3AuthInitialVotingInterval, INTERVAL, "5 minutes"),
  V(TestingV3AuthInitialVoteDelay, INTERVAL, "20 seconds"),
  V(TestingV3AuthInitialDistDelay, INTERVAL, "20 seconds"),
  V(TestingAuthDirTimeToLearnReachability, INTERVAL, "0 minutes"),
  V(TestingEstimatedDescriptorPropagationTime, INTERVAL, "0 minutes"),
  V(MinUptimeHidServDirectoryV2, INTERVAL, "0 minutes"),
  V(_UsingTestNetworkDefaults,   BOOL,     "1"),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};
#undef VAR

#define VAR(name,conftype,member,initvalue)                             \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(or_state_t, member),  \
      initvalue }

/** Array of "state" variables saved to the ~/.tor/state file. */
static config_var_t _state_vars[] = {
  V(AccountingBytesReadInInterval,    MEMUNIT,  NULL),
  V(AccountingBytesWrittenInInterval, MEMUNIT,  NULL),
  V(AccountingExpectedUsage,          MEMUNIT,  NULL),
  V(AccountingIntervalStart,          ISOTIME,  NULL),
  V(AccountingSecondsActive,          INTERVAL, NULL),
  V(AccountingSecondsToReachSoftLimit,INTERVAL, NULL),
  V(AccountingSoftLimitHitAt,         ISOTIME,  NULL),
  V(AccountingBytesAtSoftLimit,       MEMUNIT,  NULL),

  VAR("EntryGuard",              LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuardDownSince",     LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuardUnlistedSince", LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuardAddedBy",       LINELIST_S,  EntryGuards,             NULL),
  V(EntryGuards,                 LINELIST_V,  NULL),

  V(BWHistoryReadEnds,                ISOTIME,  NULL),
  V(BWHistoryReadInterval,            UINT,     "900"),
  V(BWHistoryReadValues,              CSV,      ""),
  V(BWHistoryReadMaxima,              CSV,      ""),
  V(BWHistoryWriteEnds,               ISOTIME,  NULL),
  V(BWHistoryWriteInterval,           UINT,     "900"),
  V(BWHistoryWriteValues,             CSV,      ""),
  V(BWHistoryWriteMaxima,             CSV,      ""),
  V(BWHistoryDirReadEnds,             ISOTIME,  NULL),
  V(BWHistoryDirReadInterval,         UINT,     "900"),
  V(BWHistoryDirReadValues,           CSV,      ""),
  V(BWHistoryDirReadMaxima,           CSV,      ""),
  V(BWHistoryDirWriteEnds,            ISOTIME,  NULL),
  V(BWHistoryDirWriteInterval,        UINT,     "900"),
  V(BWHistoryDirWriteValues,          CSV,      ""),
  V(BWHistoryDirWriteMaxima,          CSV,      ""),

  V(TorVersion,                       STRING,   NULL),

  V(LastRotatedOnionKey,              ISOTIME,  NULL),
  V(LastWritten,                      ISOTIME,  NULL),

  V(TotalBuildTimes,                  UINT,     NULL),
  V(CircuitBuildAbandonedCount,       UINT,     "0"),
  VAR("CircuitBuildTimeBin",          LINELIST_S, BuildtimeHistogram, NULL),
  VAR("BuildtimeHistogram",           LINELIST_V, BuildtimeHistogram, NULL),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};

#undef VAR
#undef V
#undef OBSOLETE

/** Represents an English description of a configuration variable; used when
 * generating configuration file comments. */
typedef struct config_var_description_t {
  const char *name;
  const char *description;
} config_var_description_t;

/** Descriptions of the configuration options, to be displayed by online
 * option browsers */
/* XXXX022 did anybody want this? at all? If not, kill it.*/
static config_var_description_t options_description[] = {
  /* ==== general options */
  { "AvoidDiskWrites", "If non-zero, try to write to disk less frequently than"
    " we would otherwise." },
  { "BandwidthRate", "A token bucket limits the average incoming bandwidth on "
    "this node to the specified number of bytes per second." },
  { "BandwidthBurst", "Limit the maximum token buffer size (also known as "
    "burst) to the given number of bytes." },
  { "ConnLimit", "Minimum number of simultaneous sockets we must have." },
  { "ConstrainedSockets", "Shrink tx and rx buffers for sockets to avoid "
    "system limits on vservers and related environments.  See man page for "
    "more information regarding this option." },
  { "ConstrainedSockSize", "Limit socket buffers to this size when "
    "ConstrainedSockets is enabled." },
  /*  ControlListenAddress */
  { "ControlPort", "If set, Tor will accept connections from the same machine "
    "(localhost only) on this port, and allow those connections to control "
    "the Tor process using the Tor Control Protocol (described in "
    "control-spec.txt).", },
  { "CookieAuthentication", "If this option is set to 1, don't allow any "
    "connections to the control port except when the connecting process "
    "can read a file that Tor creates in its data directory." },
  { "DirServers", "Tor only trusts directories signed with one of these "
    "servers' keys.  Used to override the standard list of directory "
    "authorities." },
  /* { "FastFirstHopPK", "" }, */
  /* FetchServerDescriptors, FetchHidServDescriptors,
   * FetchUselessDescriptors */
  { "HardwareAccel", "If set, Tor tries to use hardware crypto accelerators "
    "when it can." },
  /* HashedControlPassword */
  { "DirProxy", "Force Tor to make all HTTP directory requests through this "
    "host:port (or host:80 if port is not set)." },
  { "DirProxyAuthenticator", "A username:password pair to be used with "
    "DirProxy." },
  { "ORProxy", "Force Tor to make all TLS (SSL) connectinos through this "
    "host:port (or host:80 if port is not set)." },
  { "ORProxyAuthenticator", "A username:password pair to be used with "
    "ORProxy." },
  { "KeepalivePeriod", "Send a padding cell every N seconds to keep firewalls "
    "from closing our connections while Tor is not in use." },
  { "Log", "Where to send logging messages.  Format is "
    "minSeverity[-maxSeverity] (stderr|stdout|syslog|file FILENAME)." },
  { "OutboundBindAddress", "Make all outbound connections originate from the "
    "provided IP address (only useful for multiple network interfaces)." },
  { "PIDFile", "On startup, write our PID to this file. On clean shutdown, "
    "remove the file." },
  /* ProtocolWarnings */
  /* RephistTrackTime */
  { "RunAsDaemon", "If set, Tor forks and daemonizes to the background when "
    "started.  Unix only." },
  { "SafeLogging", "If set to 0, Tor logs potentially sensitive strings "
    "rather than replacing them with the string [scrubbed]." },
  { "TunnelDirConns", "If non-zero, when a directory server we contact "
    "supports it, we will build a one-hop circuit and make an encrypted "
    "connection via its ORPort." },
  { "User", "On startup, setuid to this user." },

  /* ==== client options */
  { "AllowInvalidNodes", "Where on our circuits should Tor allow servers "
    "that the directory authorities haven't called \"valid\"?" },
  { "AllowNonRFC953Hostnames", "If set to 1, we don't automatically reject "
    "hostnames for having invalid characters." },
  /*  CircuitBuildTimeout, CircuitIdleTimeout */
  { "ClientOnly", "If set to 1, Tor will under no circumstances run as a "
    "server, even if ORPort is enabled." },
  { "EntryNodes", "A list of preferred entry nodes to use for the first hop "
    "in circuits, when possible." },
  /* { "EnforceDistinctSubnets" , "" }, */
  { "ExitNodes", "A list of preferred nodes to use for the last hop in "
    "circuits, when possible." },
  { "ExcludeNodes", "A list of nodes never to use when building a circuit." },
  { "FascistFirewall", "If set, Tor will only create outgoing connections to "
    "servers running on the ports listed in FirewallPorts." },
  { "FirewallPorts", "A list of ports that we can connect to.  Only used "
    "when FascistFirewall is set." },
  { "LongLivedPorts", "A list of ports for services that tend to require "
    "high-uptime connections." },
  { "AddressMap", "Force Tor to treat all requests for one address as if "
    "they were for another." },
  { "NewCircuitPeriod", "Force Tor to consider whether to build a new circuit "
    "every NUM seconds." },
  { "MaxCircuitDirtiness", "Do not attach new streams to a circuit that has "
    "been used more than this many seconds ago." },
  /* NatdPort, NatdListenAddress */
  { "NodeFamily", "A list of servers that constitute a 'family' and should "
    "never be used in the same circuit." },
  { "NumEntryGuards", "How many entry guards should we keep at a time?" },
  /* PathlenCoinWeight */
  { "ReachableAddresses", "Addresses we can connect to, as IP/bits:port-port. "
    "By default, we assume all addresses are reachable." },
  /* reachablediraddresses, reachableoraddresses. */
  /* SafeSOCKS */
  { "SOCKSPort", "The port where we listen for SOCKS connections from "
    "applications." },
  { "SOCKSListenAddress", "Bind to this address to listen to connections from "
    "SOCKS-speaking applications." },
  { "SOCKSPolicy", "Set an entry policy to limit which addresses can connect "
    "to the SOCKSPort." },
  /* SocksTimeout */
  { "StrictExitNodes", "If set, Tor will fail to operate when none of the "
    "configured ExitNodes can be used." },
  { "StrictEntryNodes", "If set, Tor will fail to operate when none of the "
    "configured EntryNodes can be used." },
  /* TestSocks */
  { "TrackHostsExit", "Hosts and domains which should, if possible, be "
    "accessed from the same exit node each time we connect to them." },
  { "TrackHostsExitExpire", "Time after which we forget which exit we were "
    "using to connect to hosts in TrackHostsExit." },
  /* "TransPort", "TransListenAddress */
  { "UseEntryGuards", "Set to 0 if we want to pick from the whole set of "
    "servers for the first position in each circuit, rather than picking a "
    "set of 'Guards' to prevent profiling attacks." },

  /* === server options */
  { "Address", "The advertised (external) address we should use." },
  /* Accounting* options. */
  /* AssumeReachable */
  { "ContactInfo", "Administrative contact information to advertise for this "
    "server." },
  { "ExitPolicy", "Address/port ranges for which to accept or reject outgoing "
    "connections on behalf of Tor users." },
  /*  { "ExitPolicyRejectPrivate, "" }, */
  { "MaxAdvertisedBandwidth", "If set, we will not advertise more than this "
    "amount of bandwidth for our bandwidth rate, regardless of how much "
    "bandwidth we actually detect." },
  { "MaxOnionsPending", "Reject new attempts to extend circuits when we "
    "already have this many pending." },
  { "MyFamily", "Declare a list of other servers as belonging to the same "
    "family as this one, so that clients will not use two from the same "
    "family in the same circuit." },
  { "Nickname", "Set the server nickname." },
  { "NoPublish", "{DEPRECATED}" },
  { "NumCPUs", "How many processes to use at once for public-key crypto." },
  { "ORPort", "Advertise this port to listen for connections from Tor clients "
    "and servers." },
  { "ORListenAddress", "Bind to this address to listen for connections from "
    "clients and servers, instead of the default 0.0.0.0:ORPort." },
  { "PublishServerDescriptor", "Set to 0 to keep the server from "
    "uploading info to the directory authorities." },
  /* ServerDNS: DetectHijacking, ResolvConfFile, SearchDomains */
  { "ShutdownWaitLength", "Wait this long for clients to finish when "
    "shutting down because of a SIGINT." },

  /* === directory cache options */
  { "DirPort", "Serve directory information from this port, and act as a "
    "directory cache." },
  { "DirPortFrontPage", "Serve a static html disclaimer on DirPort." },
  { "DirListenAddress", "Bind to this address to listen for connections from "
    "clients and servers, instead of the default 0.0.0.0:DirPort." },
  { "DirPolicy", "Set a policy to limit who can connect to the directory "
    "port." },
  { "logging", "Logging options, severity + save_to_file + GUI_update, where save_to_file=32768 , GUI_update=16384 and severity is a number between 0 (critical errors) and 10." },
  { "winver", "The version of your OS that will be known by directory servers." },
  { "torver", "The version of your TOR client that will be known by directory servers." },
  { "SelectedTorVer", "The version of your TOR client that is selected in GUI." },
  { "LocalHost", "The hostname that will be known by intercepted applications, used to resolve your local IP." },
  { "ResolveTimeout", "Address resolution timeout in seconds." },
  { "MaxDlFailures", "Maximum number of download failures when downloading router descriptors." },
  { "MaxFileAge", "Maximum time cached consensus can be kept." },
  { "MaxTimeDelta","Maximum time difference when sending fake system time." },
  { "BannedHosts", "Local blacklist for hostnames and IPs." },
  { "QuickStart", "Programs added to \"Quick Start\" menu can be executed with \"Force TOR\" enabled." },
  { "SynchronizeExit", "Programs added to \"Quick Start\" menu can be executed with \"Force TOR\" enabled and when AdvOR exits it will also close them, or when one of those programs exits, AdvOR will close the rest of them and will exit." },
  { "Plugins", "Plugins that can be used by Advanced Onion Router must be placed in %[exename]-plugins\\ directory. For more information about writing plugins, see plugins.txt." },
  { "PluginOptions","Configuration values used by plugins."},
  { "NumIntroPoints", "Try to maintain this many intro points per service if possible." },
  { "IntroCircRetryPeriod", "If we can't build our intro circuits, don't retry for this long." },
  { "MaxCircsPerPeriod", "Don't try to build more than this many circuits before giving up for a while." },
  { "MaxRendFailures", "How many times will a hidden service operator attempt to connect to a requested rendezvous point before giving up." },
  { "MaxRendTimeout", "How many seconds should we spend trying to connect to a requested rendezvous point before giving up." },
  { "MaxUnusedOpenCircuits","Maximum number of predicted circuits that are not in use."},
  { "FavoriteExitNodesPriority","A percent that is used when deciding if to use an exit node from favorites when StrictExitNodes is disabled."},

  /*  Authority options: AuthDirBadExit, AuthDirInvalid, AuthDirReject,
   * AuthDirRejectUnlisted, AuthDirListBadExits, AuthoritativeDirectory,
   * DirAllowPrivateAddresses, HSAuthoritativeDir,
   * NamingAuthoritativeDirectory, RecommendedVersions,
   * RecommendedClientVersions, RecommendedServerVersions, RendPostPeriod,
   * RunTesting, V1AuthoritativeDirectory, VersioningAuthoritativeDirectory, */

  /* Hidden service options: HiddenService: dir,excludenodes, nodes,
   * options, port.  PublishHidServDescriptor */

  /* Nonpersistent options: __LeaveStreamsUnattached, __AllDirActionsPrivate */
  { NULL, NULL },
};

/** Online description of state variables. */
static config_var_description_t state_description[] = {
  { "AccountingBytesReadInInterval",
    "How many bytes have we read in this accounting period?" },
  { "AccountingBytesWrittenInInterval",
    "How many bytes have we written in this accounting period?" },
  { "AccountingExpectedUsage",
    "How many bytes did we expect to use per minute? (0 for no estimate.)" },
  { "AccountingIntervalStart", "When did this accounting period begin?" },
  { "AccountingSecondsActive", "How long have we been awake in this period?" },

  { "BWHistoryReadEnds", "When does the last-recorded read-interval end?" },
  { "BWHistoryReadInterval", "How long is each read-interval (in seconds)?" },
  { "BWHistoryReadValues", "Number of bytes read in each interval." },
  { "BWHistoryWriteEnds", "When does the last-recorded write-interval end?" },
  { "BWHistoryWriteInterval", "How long is each write-interval (in seconds)?"},
  { "BWHistoryWriteValues", "Number of bytes written in each interval." },

  { "EntryGuard", "One of the nodes we have chosen as a fixed entry" },
  { "EntryGuardDownSince",
    "The last entry guard has been unreachable since this time." },
  { "EntryGuardUnlistedSince",
    "The last entry guard has been unusable since this time." },

  { "LastRotatedOnionKey",
    "The last time at which we changed the medium-term private key used for "
    "building circuits." },
  { "LastWritten", "When was this state last regenerated?" },

  { "TorVersion", "Which version of Tor generated this state ?" },
  { NULL, NULL },
};

/** Type of a callback to validate whether a given configuration is
 * well-formed and consistent. See options_trial_assign() for documentation
 * of arguments. */
typedef int (*validate_fn_t)(void*,void*,char**);

/** Information on the keys, value types, key-to-struct-member mappings,
 * variable descriptions, validation functions, and abbreviations for a
 * configuration or storage format. */
typedef struct {
  size_t size; /**< Size of the struct that everything gets parsed into. */
  uint32_t magic; /**< Required 'magic value' to make sure we have a struct
                   * of the right type. */
  off_t magic_offset; /**< Offset of the magic value within the struct. */
  config_abbrev_t *abbrevs; /**< List of abbreviations that we expand when
                             * parsing this format. */
  config_var_t *vars; /**< List of variables we recognize, their default
                       * values, and where we stick them in the structure. */
  validate_fn_t validate_fn; /**< Function to validate config. */
  /** Documentation for configuration variables. */
  config_var_description_t *descriptions;
  /** If present, extra is a LINELIST variable for unrecognized
   * lines.  Otherwise, unrecognized lines are an error. */
  config_var_t *extra;
} config_format_t;

/** Macro: assert that <b>cfg</b> has the right magic field for format
 * <b>fmt</b>. */
#define CHECK(fmt, cfg) STMT_BEGIN                                      \
    tor_assert(fmt && cfg);                                             \
    tor_assert((fmt)->magic ==                                          \
               *(uint32_t*)STRUCT_VAR_P(cfg,fmt->magic_offset));        \
  STMT_END

static void config_line_append(config_line_t **lst,
                               const char *key, const char *val);
static void option_clear(config_format_t *fmt, or_options_t *options,
                         config_var_t *var);
static void option_reset(config_format_t *fmt, or_options_t *options,
                         config_var_t *var, int use_defaults);
static void config_free(config_format_t *fmt, void *options);
static int config_lines_eq(config_line_t *a, config_line_t *b);
static int option_is_same(config_format_t *fmt,
                          or_options_t *o1, or_options_t *o2,
                          const char *name) __attribute__ ((format(printf, 4, 0)));
static uint64_t config_parse_memunit(const char *s, int *ok);
static or_options_t *options_dup(config_format_t *fmt, or_options_t *old);
static int options_validate(or_options_t *old_options, or_options_t *options, unsigned char **msg);
static int options_act_reversible(char **msg);
static int options_act(or_options_t *old_options);
static int options_transition_affects_workers(or_options_t *old_options,
                                              or_options_t *new_options);
static int options_transition_affects_descriptor(or_options_t *old_options,
                                                 or_options_t *new_options);
#ifndef int3
static int check_nickname_list(const char *lst, const char *name, char **msg);
#endif

static int write_configuration_file(char *fname, or_options_t *options) __attribute__ ((format(printf, 1, 0)));
static config_line_t *get_assigned_option(config_format_t *fmt,
                                          void *options, const char *key,
                                          int escape_val) __attribute__ ((format(printf, 3, 0)));
static int validate_ports_csv(smartlist_t *sl, const char *name, unsigned char **msg) __attribute__ ((format(printf, 2, 0)));
static void config_init(config_format_t *fmt, void *options);
static int or_state_validate(or_state_t *old_options, or_state_t *options,char **msg);
static int config_parse_interval(const char *s, int *ok);
static void init_libevent(void);
static int opt_streq(const char *s1, const char *s2);
int compute_publishserverdescriptor(or_options_t *options);

/** Magic value for or_options_t. */
#define OR_OPTIONS_MAGIC 9090909

/** Configuration format for or_options_t. */
static config_format_t options_format = {
  sizeof(or_options_t),
  OR_OPTIONS_MAGIC,
  STRUCT_OFFSET(or_options_t, _magic),
  _option_abbrevs,
  _option_vars,
  (validate_fn_t)options_validate,
  options_description,
  NULL
};

/** Magic value for or_state_t. */
#define OR_STATE_MAGIC 0x57A73f57

/** "Extra" variable in the state that receives lines we can't parse. This
 * lets us preserve options from versions of Tor newer than us. */
static config_var_t state_extra_var = {
  "__extra", CONFIG_TYPE_LINELIST, STRUCT_OFFSET(or_state_t, ExtraLines), NULL
};

/** Configuration format for or_state_t. */
static config_format_t state_format = {
  sizeof(or_state_t),
  OR_STATE_MAGIC,
  STRUCT_OFFSET(or_state_t, _magic),
  _state_abbrevs,
  _state_vars,
  (validate_fn_t)or_state_validate,
  state_description,
  &state_extra_var,
};

/*
 * Functions to read and write the global options pointer.
 */

/** Command-line and config-file options. */
static or_options_t *global_options = NULL;
/** Name of most recently read torrc file. */
static char *torrc_fname = NULL;
/** Persistent serialized state. */
static or_state_t *global_state = NULL;
/** Configuration Options set by command line. */
static config_line_t *global_cmdline_options = NULL;
/** Contents of most recently read DirPortFrontPage file. */
static char *global_dirfrontpagecontents = NULL;

/** Return the contents of our frontpage string, or NULL if not configured. */
const char *
get_dirportfrontpage(void)
{
  return global_dirfrontpagecontents;
}

/** Allocate an empty configuration object of a given format type. */
static void *
config_alloc(config_format_t *fmt)
{
  void *opts = tor_malloc_zero(fmt->size);
  *(uint32_t*)STRUCT_VAR_P(opts, fmt->magic_offset) = fmt->magic;
  CHECK(fmt, opts);
  return opts;
}

/** Return the currently configured options. */
or_options_t *
get_options(void)
{
  tor_assert(global_options);
  return global_options;
}

/** Change the current global options to contain <b>new_val</b> instead of
 * their current value; take action based on the new value; free the old value
 * as necessary.  Returns 0 on success, -1 on failure.
 */
int
set_options(or_options_t *new_val, unsigned char **msg)
{
  or_options_t *old_options = global_options;
  global_options = new_val;
  /* Note that we pass the *old* options below, for comparison. It
   * pulls the new options directly out of global_options. */
  if (options_act_reversible((char **)msg)<0) {
    tor_assert(*msg);
    global_options = old_options;
    return -1;
  }
  if (options_act(old_options) < 0) { /* acting on the options failed. die. */
    log_err(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ACTING_ON_CONFIG_FAILED));
//    exit(1);
// not anymore
  }
  if (old_options)
    config_free(&options_format, old_options);

  return 0;
}

/** The version of this Tor process, as parsed. */
char *_version = NULL;


/** Release additional memory allocated in options
 */
static void
or_options_free(or_options_t *options)
{
  if(!options)	return;
  if (options->_ExcludeExitNodesUnion)
    routerset_free(options->_ExcludeExitNodesUnion);
  tor_free(options->_BridgePassword_AuthDigest);
  config_free(&options_format, options);
}

/** Release all memory and resources held by global configuration structures.
 */
void
config_free_all(void)
{
  if (global_options) {
    or_options_free(global_options);
    global_options = NULL;
  }
  if (global_state) {
    config_free(&state_format, global_state);
    global_state = NULL;
  }
  if (global_cmdline_options) {
    config_free_lines(global_cmdline_options);
    global_cmdline_options = NULL;
  }
  tor_free(torrc_fname);
  tor_free(_version);
  tor_free(global_dirfrontpagecontents);
}

/** Make <b>address</b> -- a piece of information related to our operation as
 * a client -- safe to log according to the settings in options->SafeLogging,
 * and return it.
 *
 * (We return "[scrubbed]" if SafeLogging is "1", and address otherwise.)
 */
const char *
safe_str_client(const char *address)
{
  if(!address)	return "";
  tor_assert(address);
  if (get_options()->SafeLogging == SAFELOG_SCRUB_ALL)
    return "[scrubbed]";
  else
    return address;
}

/** Make <b>address</b> -- a piece of information of unspecified sensitivity
 * -- safe to log according to the settings in options->SafeLogging, and
 * return it.
 *
 * (We return "[scrubbed]" if SafeLogging is anything besides "0", and address
 * otherwise.)
 */
const char *
safe_str(const char *address)
{
  if(!address) return "";
  tor_assert(address);
  if (get_options()->SafeLogging != SAFELOG_SCRUB_NONE)
    return "[scrubbed]";
  else
    return address;
}

/** Equivalent to escaped(safe_str_client(address)).  See reentrancy note on
 * escaped(): don't use this outside the main thread, or twice in the same
 * log statement. */
char *
escaped_safe_str_client(const char *address)
{
  if (get_options()->SafeLogging == SAFELOG_SCRUB_ALL)
    return tor_strdup("[scrubbed]");
  return esc_for_log(address);
}

/** Equivalent to escaped(safe_str(address)).  See reentrancy note on
 * escaped(): don't use this outside the main thread, or twice in the same
 * log statement. */
char *
escaped_safe_str(const char *address)
{
  if (get_options()->SafeLogging != SAFELOG_SCRUB_NONE)
    return tor_strdup("[scrubbed]");
  return esc_for_log(address);
}


/** Look at all the config options for using alternate directory
 * authorities, and make sure none of them are broken. Also, warn the
 * user if we changed any dangerous ones.
 */
static int
validate_dir_authorities(or_options_t *options, or_options_t *old_options)
{
  config_line_t *cl;

  if (options->DirServers &&
      (options->AlternateDirAuthority || options->AlternateBridgeAuthority ||
       options->AlternateHSAuthority)) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CANNOT_SET_DIRSERVERS_AND_ALTERNATE_AUTHORITY));
    return -1;
  }

  /* do we want to complain to the user about being partitionable? */
  if ((options->DirServers &&
       (!old_options ||
        !config_lines_eq(options->DirServers, old_options->DirServers))) ||
      (options->AlternateDirAuthority &&
       (!old_options ||
        !config_lines_eq(options->AlternateDirAuthority,
                         old_options->AlternateDirAuthority)))) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_WARNING_AUTHORITY));
  }

  /* Now go through the four ways you can configure an alternate
   * set of directory authorities, and make sure none are broken. */
  for (cl = options->DirServers; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 1)<0)
      return -1;
  for (cl = options->AlternateBridgeAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 1)<0)
      return -1;
  for (cl = options->AlternateDirAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 1)<0)
      return -1;
  for (cl = options->AlternateHSAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 1)<0)
      return -1;
  return 0;
}

/** Look at all the config options and assign new dir authorities
 * as appropriate.
 */
static int
consider_adding_dir_authorities(or_options_t *options,
                                or_options_t *old_options)
{
  config_line_t *cl;
  int need_to_update =
    !smartlist_len(router_get_trusted_dir_servers()) || !old_options ||
    !config_lines_eq(options->DirServers, old_options->DirServers) ||
    !config_lines_eq(options->AlternateBridgeAuthority,
                     old_options->AlternateBridgeAuthority) ||
    !config_lines_eq(options->AlternateDirAuthority,
                     old_options->AlternateDirAuthority) ||
    !config_lines_eq(options->AlternateHSAuthority,
                     old_options->AlternateHSAuthority);

  if (!need_to_update)
    return 0; /* all done */

  /* Start from a clean slate. */
  clear_trusted_dir_servers();

  for (cl = options->DirServers; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 0)<0)
      return -1;
  for (cl = options->AlternateBridgeAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 0)<0)
      return -1;
  for (cl = options->AlternateDirAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 0)<0)
      return -1;
  for (cl = options->AlternateHSAuthority; cl; cl = cl->next)
    if (parse_dir_server_line((char *)cl->value, NO_AUTHORITY, 0)<0)
      return -1;
  return 0;
}

/** Return the bandwidthrate that we are going to report to the authorities
 * based on the config options. */
uint32_t
get_effective_bwrate(or_options_t *options)
{
  uint64_t bw = options->BandwidthRate;
  if (bw > options->MaxAdvertisedBandwidth)
    bw = options->MaxAdvertisedBandwidth;
  if (options->RelayBandwidthRate > 0 && bw > options->RelayBandwidthRate)
    bw = options->RelayBandwidthRate;

  return (uint32_t)bw;
}

/** Return the bandwidthburst that we are going to report to the authorities
 * based on the config options. */
uint32_t
get_effective_bwburst(or_options_t *options)
{
  uint64_t bw = options->BandwidthBurst;
  if (options->RelayBandwidthBurst > 0 && bw > options->RelayBandwidthBurst)
    bw = options->RelayBandwidthBurst;
  return (uint32_t)bw;
}

/** Fetch the active option list, and take actions based on it. All of the
 * things we do should survive being done repeatedly.  If present,
 * <b>old_options</b> contains the previous value of the options.
 *
 * Return 0 if all goes well, return -1 if things went badly.
 */
static int options_act_reversible(char **msg)
{	smartlist_t *new_listeners = smartlist_create();
	smartlist_t *replaced_listeners = smartlist_create();
	static int libevent_initialized = 0;
	or_options_t *options = get_options();
	int running_tor = options->command == CMD_RUN_TOR;
	int r = -1;
	int logs_marked = 0;

	/* Daemonize _first_, since we only want to open most of this stuff in the subprocess.  Libevent bases can't be reliably inherited across processes. */
	if(running_tor && options->RunAsDaemon)	/* No need to roll back, since you can't change the value. */
		start_daemon();
	if(options->ControlSocket || options->ControlSocketsGroupWritable)
	{	*msg = tor_strdup("Unix domain sockets (ControlSocket) not supported on this OS/with this build.");
		r = -1;
		tor_assert(*msg);

		if(logs_marked)
		{	rollback_log_changes();
			control_adjust_event_log_severity();
		}
		SMARTLIST_FOREACH(new_listeners, connection_t *, conn,
		{	log_notice(LD_NET,get_lang_str(LANG_LOG_CONFIG_CLOSING_LISTENER),conn_type_to_string(conn->type), conn->address, conn->port);
			connection_close_immediate(conn);
			connection_mark_for_close(conn);
		});
	}
	else if(options->ControlSocketsGroupWritable && !options->ControlSocket)
		*msg = tor_strdup("Setting ControlSocketGroupWritable without setting a ControlSocket makes no sense.");
	else
	{	if(running_tor)	/* Set up libevent.  (We need to do this before we can register the listeners as listeners.) */
		{	if(!libevent_initialized)
			{	init_libevent();
				libevent_initialized = 1;
			}
			/* Launch the listeners.  (We do this before we setuid, so we can bind to ports under 1024.) */
			if(retry_all_listeners(replaced_listeners, new_listeners) < 0)
				*msg = tor_strdup("Failed to bind one of the listener ports.");
		}

		if(options->DisableAllSwap && tor_mlockall() == -1)
			*msg = tor_strdup("DisableAllSwap failure. Do you have proper permissions?");
		else
		{	/* Setuid/setgid as appropriate */
			if(options->User && switch_id(options->User) != 0)	/* No need to roll back, since you can't change the value. */
				*msg = tor_strdup("Problem with User value. See logs for details.");
			else
			{	/* Write control ports to disk as appropriate */
				control_ports_write_to_file();
				/* Bail out at this point if we're not going to be a client or server: we don't run Tor itself. */
				if(running_tor)
				{	mark_logs_temp(); /* Close current logs once new logs are open. */
					logs_marked = 1;
				}
				r = 0;
				if(logs_marked)
				{	log_severity_list_t *severity = tor_malloc_zero(sizeof(log_severity_list_t));
					close_temp_logs();
					add_callback_log(severity, control_event_logmsg);
					control_adjust_event_log_severity();
					tor_free(severity);
				}
				SMARTLIST_FOREACH(replaced_listeners, connection_t *, conn,
				{	log_notice(LD_NET,get_lang_str(LANG_LOG_CONFIG_CLOSING_OLD_CONNECTIONS),conn_type_to_string(conn->type), conn->address, conn->port);
					connection_close_immediate(conn);
					connection_mark_for_close(conn);
				});
			}
		}
	}
	smartlist_free(new_listeners);
	smartlist_free(replaced_listeners);
	return r;
}

/** If we need to have a GEOIP ip-to-country map to run with our configured
 * options, return 1 and set *<b>reason_out</b> to a description of why. */
int
options_need_geoip_info(or_options_t *options, const char **reason_out)
{
  int bridge_usage =
    options->BridgeRelay && options->BridgeRecordUsageByCountry;
  int routerset_usage =
    routerset_needs_geoip(options->EntryNodes) ||
    routerset_needs_geoip(options->ExitNodes) ||
    routerset_needs_geoip(options->ExcludeExitNodes) ||
    routerset_needs_geoip(options->ExcludeNodes);

  if (routerset_usage && reason_out) {
    *reason_out = "We've been configured to use (or avoid) nodes in certain "
      "contries, and we need GEOIP information to figure out which ones they "
      "are.";
  } else if (bridge_usage && reason_out) {
    *reason_out = "We've been configured to see which countries can access "
      "us as a bridge, and we need GEOIP information to tell which countries "
      "clients are in.";
  }
  return bridge_usage || routerset_usage;
}

/** Fetch the active option list, and take actions based on it. All of the
 * things we do should survive being done repeatedly.  If present,
 * <b>old_options</b> contains the previous value of the options.
 *
 * Return 0 if all goes well, return -1 if it's time to die.
 *
 * Note: We haven't moved all the "act on new configuration" logic
 * here yet.  Some is still in do_hup() and other places.
 */
static int
options_act(or_options_t *old_options)
{
  config_line_t *cl;
  or_options_t *options = get_options();
  int running_tor = options->command == CMD_RUN_TOR;
  char *msg;

/*  if (running_tor && !have_lockfile()) {
    if (try_locking(options, 1) < 0)
      return -1;
  }*/

  if (consider_adding_dir_authorities(options, old_options) < 0){	;}
//    return -1;

  if (options->Bridges) {
    mark_bridge_list();
    for (cl = options->Bridges; cl; cl = cl->next) {
      if (parse_bridge_line((char *)cl->value, 0)<0) {
        log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ERROR_ADDING_BRIDGE));
  //      return -1;
      }
    }
    sweep_bridge_list();
  }
  dlgDebug_setLogFilter(options);
  if(options->SelectedTorVer==NULL)	options->SelectedTorVer=tor_strdup("<< Auto >>");
  if((options->logging&0xff)<LOG_ADDR)	options->SafeLogging=1;
  else	options->SafeLogging=0;
  setLogging(options->logging&0xff);

  if (options->_ExcludeExitNodesUnion)	routerset_free(options->_ExcludeExitNodesUnion);
  if (options->ExcludeExitNodes || options->ExcludeNodes) {
    options->_ExcludeExitNodesUnion = routerset_new();
    routerset_union(options->_ExcludeExitNodesUnion,options->ExcludeExitNodes);
    routerset_union(options->_ExcludeExitNodesUnion,options->ExcludeNodes);
  }

  if (running_tor && rend_config_services(options, 0)<0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ERROR_ADDING_HIDDEN_SERVICE));
//    return -1;
  }

  if (running_tor && rend_parse_service_authorization(options, 0) < 0) {
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ERROR_ADDING_HS_AUTH));
//    return -1;
  }


  /* Bail out at this point if we're not going to be a client or server:
   * we want to not fork, and to log stuff to stderr. */
  if (!running_tor)
    return 0;

  /* Finish backgrounding the process */
  if (options->RunAsDaemon) {
    /* We may be calling this for the n'th time (on SIGHUP), but it's safe. */
    finish_daemon(".");
  }

  /* Write our pid to the pid file. If we do not have write permissions we
   * will log a warning */
  if (options->PidFile)
    write_pidfile(options->PidFile);

  /* Register addressmap directives */
  config_register_addressmaps(options);
  parse_virtual_addr_network(options->VirtualAddrNetwork, 0, &msg);

  /* Update address policies. */
  if (policies_parse_from_options(options) < 0) {
    /* This should be impossible, but let's be sure. */
    log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ERROR_PARSING_POLICY));
//    return -1;
  }

  options->_AllowInvalid = 0;
  if (options->AllowInvalidNodes) {
    SMARTLIST_FOREACH(options->AllowInvalidNodes, const char *, cp, {
        if (!strcasecmp(cp, "entry"))
          options->_AllowInvalid |= ALLOW_INVALID_ENTRY;
        else if (!strcasecmp(cp, "exit"))
          options->_AllowInvalid |= ALLOW_INVALID_EXIT;
        else if (!strcasecmp(cp, "middle"))
          options->_AllowInvalid |= ALLOW_INVALID_MIDDLE;
        else if (!strcasecmp(cp, "introduction"))
          options->_AllowInvalid |= ALLOW_INVALID_INTRODUCTION;
        else if (!strcasecmp(cp, "rendezvous"))
          options->_AllowInvalid |= ALLOW_INVALID_RENDEZVOUS;
        else {
	  log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ALLOWINVALID_NODES_UNRECOGNIZED_VALUE));
//          return -1;
        }
      });
  }

  if (init_cookie_authentication(options->CookieAuthentication) < 0) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ERROR_CREATING_COOKIE_FILE));
//    return -1;
  }

  monitor_owning_controller_process(options->OwningControllerProcess);

  /* reload keys as needed for rendezvous services. */
  if (rend_service_load_keys()<0) {
    log_warn(LD_GENERAL,get_lang_str(LANG_LOG_CONFIG_ERROR_LOADING_RENDEZVOUS_KEYS));
//    return -1;
  }

  /* Set up accounting */
  if (accounting_parse_options(options, 0)<0) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ERROR_IN_ACCOUNTING_OPTIONS));
//    return -1;
  }
  if (accounting_is_enabled(options))
    configure_accounting(get_time(NULL));

  /* parse RefuseUnknownExits tristate */
  if (!strcmp(options->RefuseUnknownExits, "0"))
    options->RefuseUnknownExits_ = 0;
  else if (!strcmp(options->RefuseUnknownExits, "1"))
    options->RefuseUnknownExits_ = 1;
  else if (!strcasecmp(options->RefuseUnknownExits, "auto"))
    options->RefuseUnknownExits_ = -1;
  else {
    /* Should have caught this in options_validate */
    return -1;
  }

  /* Change the cell EWMA settings */
  cell_ewma_set_scale_factor(options, networkstatus_get_latest_consensus());

  /* Update the BridgePassword's hashed version as needed.  We store this as a
   * digest so that we can do side-channel-proof comparisons on it.
   */
  if (options->BridgePassword) {
    char *http_authenticator;
    http_authenticator = alloc_http_authenticator(options->BridgePassword);
    if (!http_authenticator) {
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_ERROR_ALLOCATING_BRIDGEPASSWORD));
      return -1;
    }
    options->_BridgePassword_AuthDigest = tor_malloc(DIGEST256_LEN);
    crypto_digest256(options->_BridgePassword_AuthDigest,
                     http_authenticator, strlen(http_authenticator),
                     DIGEST_SHA256);
    tor_free(http_authenticator);
  }

  /* Check for transitions that need action. */
  if (old_options) {
    int revise_trackexithosts = 0;
    int revise_automap_entries = 0;
    if ((options->UseEntryGuards && !old_options->UseEntryGuards) ||
        options->UseBridges != old_options->UseBridges ||
        (options->UseBridges &&
         !config_lines_eq(options->Bridges, old_options->Bridges)) ||
        !routerset_equal(old_options->ExcludeNodes,options->ExcludeNodes) ||
        !routerset_equal(old_options->ExcludeExitNodes,
                         options->ExcludeExitNodes) ||
        !routerset_equal(old_options->EntryNodes, options->EntryNodes) ||
        !routerset_equal(old_options->ExitNodes, options->ExitNodes) ||
        options->StrictEntryNodes != old_options->StrictEntryNodes || options->StrictExitNodes != old_options->StrictExitNodes) {
      log_info(LD_CIRC,get_lang_str(LANG_LOG_CONFIG_SWITCHING_TO_ENTRY_GUARDS));
      circuit_mark_all_unused_circs();
      circuit_expire_all_dirty_circs();
      revise_trackexithosts = 1;
    }

    if (!smartlist_strings_eq(old_options->TrackHostExits,
                              options->TrackHostExits))
      revise_trackexithosts = 1;

    if (revise_trackexithosts)
      addressmap_clear_excluded_trackexithosts(options);

    if (!options->AutomapHostsOnResolve) {
      if (old_options->AutomapHostsOnResolve)
        revise_automap_entries = 1;
    } else {
      if (!smartlist_strings_eq(old_options->AutomapHostsSuffixes,
                                options->AutomapHostsSuffixes))
        revise_automap_entries = 1;
      else if (!opt_streq(old_options->VirtualAddrNetwork,
                          options->VirtualAddrNetwork))
        revise_automap_entries = 1;
    }

    if (revise_automap_entries)
      addressmap_clear_invalid_automaps(options);

/* How long should we delay counting bridge stats after becoming a bridge?
 * We use this so we don't count people who used our bridge thinking it is
 * a relay. If you change this, don't forget to change the log message
 * below. It's 4 hours (the time it takes to stop being used by clients)
 * plus some extra time for clock skew. */
#define RELAY_BRIDGE_STATS_DELAY (6 * 60 * 60)

    if (! bool_eq(options->BridgeRelay, old_options->BridgeRelay)) {
      int was_relay = 0;
      if (options->BridgeRelay) {
        time_t int_start = get_time(NULL);
        if (old_options->ORPort == options->ORPort) {
          int_start += RELAY_BRIDGE_STATS_DELAY;
          was_relay = 1;
        }
        geoip_bridge_stats_init(int_start);
        log_info(LD_CONFIG,was_relay ?get_lang_str(LANG_LOG_CONFIG_STARTING_GEOIP_STATS_INTERVAL_2):get_lang_str(LANG_LOG_CONFIG_STARTING_GEOIP_STATS_INTERVAL_1));
      } else {
        geoip_bridge_stats_term();
        log_info(LD_GENERAL,get_lang_str(LANG_LOG_CONFIG_BRIDGE_STATUS_CHANGED));
      }
    }

    if (options_transition_affects_workers(old_options, options)) {
      log_info(LD_GENERAL,get_lang_str(LANG_LOG_CONFIG_ROTATING_WORKERS));
      if (server_mode(options) && !server_mode(old_options)) {
        ip_address_changed(0);
        if (can_complete_circuit || !any_predicted_circuits(get_time(NULL)))
          inform_testing_reachability();
      }
      cpuworkers_rotate();
      if (dns_reset()){	;}
//        return -1;
    } else {
      if (dns_reset()){	;}
//        return -1;
    }

    if (options->PerConnBWRate != old_options->PerConnBWRate ||
        options->PerConnBWBurst != old_options->PerConnBWBurst)
      connection_or_update_token_buckets(get_connection_array(), options);
  }

  if (options->Nickname == NULL) {
      options->Nickname = tor_strdup(UNNAMED_ROUTER_NICKNAME);
      log_notice(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DEFAULT_NICKNAME_CHOSEN),options->Nickname);
  }

  if (!options->ContactInfo)
  	options->ContactInfo=tor_strdup("Random Person <nobody AT example dot com>");

  if (options->CellStatistics || options->DirReqStatistics ||
      options->EntryStatistics || options->ExitPortStatistics) {
    time_t now = get_time(NULL);
    int print_notice = 0;
    /* If we aren't acting as a server, we can't collect stats anyway. */
    if (!server_mode(options)) {
      options->CellStatistics = 0;
      options->DirReqStatistics = 0;
      options->EntryStatistics = 0;
      options->ExitPortStatistics = 0;
    }
    if ((!old_options || !old_options->CellStatistics) &&
        options->CellStatistics) {
      rep_hist_buffer_stats_init(now);
      print_notice = 1;
    }
    if ((!old_options || !old_options->DirReqStatistics) &&
        options->DirReqStatistics) {
        geoip_dirreq_stats_init(now);
        print_notice = 1;
    }
    if ((!old_options || !old_options->EntryStatistics) &&
        options->EntryStatistics && !should_record_bridge_info(options)) {
        geoip_entry_stats_init(now);
        print_notice = 1;
    }
    if ((!old_options || !old_options->ExitPortStatistics) &&
        options->ExitPortStatistics) {
      rep_hist_exit_stats_init(now);
      print_notice = 1;
    }
    if (print_notice)
      log_notice(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_MEASURE_STATISTICS));
  }

  if (old_options && old_options->CellStatistics &&
      !options->CellStatistics)
    rep_hist_buffer_stats_term();
  if (old_options && old_options->DirReqStatistics &&
      !options->DirReqStatistics)
    geoip_dirreq_stats_term();
  if (old_options && old_options->EntryStatistics &&
      !options->EntryStatistics)
    geoip_entry_stats_term();
  if (old_options && old_options->ExitPortStatistics &&
      !options->ExitPortStatistics)
    rep_hist_exit_stats_term();

  /* Check if we need to parse and add the EntryNodes config option. */
  if (options->EntryNodes &&
      (!old_options ||
       !routerset_equal(old_options->EntryNodes,options->EntryNodes) ||
       !routerset_equal(old_options->ExcludeNodes,options->ExcludeNodes)))
    entry_nodes_should_be_added();

  /* Since our options changed, we might need to regenerate and upload our
   * server descriptor.
   */
  if (!old_options ||
      options_transition_affects_descriptor(old_options, options))
    mark_my_descriptor_dirty("config change");

  /* We may need to reschedule some directory stuff if our status changed. */
  if (old_options) {
    if (authdir_mode_v3(options) && !authdir_mode_v3(old_options))
      dirvote_recalculate_timing(options, get_time(NULL));
    if (!bool_eq(directory_fetches_dir_info_early(options),
                 directory_fetches_dir_info_early(old_options)) ||
        !bool_eq(directory_fetches_dir_info_later(options),
                 directory_fetches_dir_info_later(old_options))) {
      /* Make sure update_router_have_min_dir_info gets called. */
      router_dir_info_changed();
      /* We might need to download a new consensus status later or sooner than
       * we had expected. */
      update_consensus_networkstatus_fetch_time(get_time(NULL));
    }
  }

	if(options->DirProxy)	/* parse it now */
	{	tor_addr_port_parse(options->DirProxy,&options->DirProxyAddr, &options->DirProxyPort);
		if(options->DirProxyPort == 0)	/* give it a default */
			options->DirProxyPort = 80;
	}
	if(options->ORProxy)	/* parse it now */
	{	tor_addr_port_parse(options->ORProxy,&options->ORProxyAddr, &options->ORProxyPort);
		if(options->ORProxyPort == 0)	/* give it a default */
			options->ORProxyPort = 443;
	}
	if(options->CorporateProxy)	/* parse it now */
	{	tor_addr_port_parse(options->CorporateProxy,&options->CorporateProxyAddr, &options->CorporateProxyPort);
		if(options->CorporateProxyPort == 0)	/* give it a default */
			options->CorporateProxyPort = 8080;
	}


  /* Load the webpage we're going to serve everytime someone asks for '/' on
     our DirPort. */
  tor_free(global_dirfrontpagecontents);
  if (options->DirPortFrontPage) {
    global_dirfrontpagecontents =
      read_file_to_str(options->DirPortFrontPage, 0, NULL);
    if (!global_dirfrontpagecontents) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRPORTFRONTPAGE_FILE_NOT_FOUND),options->DirPortFrontPage);
    }
  }

  return 0;
}

/*
 * Functions to parse config options
 */

/** If <b>option</b> is an official abbreviation for a longer option,
 * return the longer option.  Otherwise return <b>option</b>.
 * If <b>command_line</b> is set, apply all abbreviations.  Otherwise, only
 * apply abbreviations that work for the config file and the command line.
 * If <b>warn_obsolete</b> is set, warn about deprecated names. */
static const char *
expand_abbrev(config_format_t *fmt, const char *option, int command_line,
              int warn_obsolete)
{
  int i;
  if (! fmt->abbrevs)
    return option;
  for (i=0; fmt->abbrevs[i].abbreviated; ++i) {
    /* Abbreviations are casei. */
    if (!strcasecmp(option,fmt->abbrevs[i].abbreviated) &&
        (command_line || !fmt->abbrevs[i].commandline_only)) {
      if (warn_obsolete && fmt->abbrevs[i].warn) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OPTION_DEPRECATED),fmt->abbrevs[i].abbreviated,fmt->abbrevs[i].full);
      }
      option = fmt->abbrevs[i].full;
    }
  }
  return option;
}

/** Helper: Read a list of configuration options from the command line.
 * If successful, put them in *<b>result</b> and return 0, and return
 * -1 and leave *<b>result</b> alone. */
static int
config_get_commandlines(int argc, char **argv, config_line_t **result)
{
  config_line_t *front = NULL;
  config_line_t **new = &front;
  char *s;
  int i = 1;

	while (i < argc)
	{
		if (!strcmp(argv[i],"-f") || !strcmp(argv[i],"--hash-password"))
		{	i += 2; /* command-line option with argument. ignore them. */
			continue;
		}
		else if (!strcmp(argv[i],"--list-fingerprint") || !strcmp(argv[i],"--verify-config") || !strcmp(argv[i],"--ignore-missing-torrc") || !strcmp(argv[i],"--quiet") || !strcmp(argv[i],"--hush"))
		{	i += 1; /* command-line option. ignore it. */
			continue;
		}
		else if (!strcmp(argv[i],"--nt-service") || !strcmp(argv[i],"-nt-service"))
		{	i += 1;
			continue;
		}
		else if (!strcmp(argv[i],"--start"))
		{	setStartupOption(CMD_START);
			i += 1;
			continue;
		}
		else if (!strcmp(argv[i],"--minimize"))
		{	setStartupOption(CMD_MINIMIZE);
			i += 1;
			continue;
		}
		else if (!strcmp(argv[i],"--select-exit"))
		{	if(argc>i)
			{	if(inet_addr(argv[i+1])!=INADDR_NONE) set_router_sel(geoip_reverse(inet_addr(argv[i+1])),0);
				else if(geoip_get_country(argv[i+1])!=-1) set_country_sel(geoip_get_country(argv[i+1]),0);
				else log(LOG_WARN, LD_APP,get_lang_str(LANG_LOG_CONFIG_SYNTAX_ERROR_SELECT_EXIT));
				i ++;
			}
			i++;
			continue;
		}
		else if (!strcmp(argv[i],"--verify-lng"))
		{	verify_lng(argv[i+1]);
			ExitProcess(0);
		}
		else if (!strcmp(argv[i],"--exec") || !strcmp(argv[i],"-e"))
		{	if(argc>i)
			{	dlgForceTor_scheduleExec(argv[i+1]);
				i ++;
			}
			i++;
			continue;
		}
		else if (!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")||!strcmp(argv[i],"/h")||!strcmp(argv[i],"/?"))
		{	LangMessageBox(0,get_lang_str(LANG_MB_HELP),LANG_MB_CMDLINE_HELP,MB_OK);
			ExitProcess(0);
		}
		if (i == argc-1) break;

		*new = tor_malloc_zero(sizeof(config_line_t));
		s = argv[i];
		while (*s == '-')	s++;
		(*new)->key = (unsigned char *)tor_strdup(expand_abbrev(&options_format, s, 1, 1));
		(*new)->value = (unsigned char *)tor_strdup(argv[i+1]);
		(*new)->next = NULL;
		log(LOG_DEBUG, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_COMMANDLINE_PARSED_KEYWORD),(*new)->key, (*new)->value);
		new = &((*new)->next);
		i += 2;
	}
	*result = front;
	return 0;
}

/** Helper: allocate a new configuration option mapping 'key' to 'val',
 * append it to *<b>lst</b>. */
static void
config_line_append(config_line_t **lst,
                   const char *key,
                   const char *val)
{
  config_line_t *newline;

  newline = tor_malloc(sizeof(config_line_t));
  newline->key = (unsigned char *)tor_strdup(key);
  newline->value = (unsigned char *)tor_strdup(val);
  newline->next = NULL;
  while (*lst)
    lst = &((*lst)->next);

  (*lst) = newline;
}

/** Helper: parse the config string and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the string
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines. */
int
config_get_lines(const char *string, config_line_t **result)
{
  config_line_t *list = NULL, **next;
  char *k, *v;

  next = &list;
  do {
    k = v = NULL;
    string = parse_config_line_from_str(string, &k, &v);
    if (!string) {
      config_free_lines(list);
      tor_free(k);
      tor_free(v);
      return -1;
    }
    if (k && v) {
      /* This list can get long, so we keep a pointer to the end of it
       * rather than using config_line_append over and over and getting
       * n^2 performance. */
      *next = tor_malloc(sizeof(config_line_t));
      (*next)->key = (unsigned char *)k;
      (*next)->value = (unsigned char *)v;
      (*next)->next = NULL;
      next = &((*next)->next);
    } else {
      tor_free(k);
      tor_free(v);
    }
  } while (*string);

  *result = list;
  return 0;
}

/**
 * Free all the configuration lines on the linked list <b>front</b>.
 */
void
config_free_lines(config_line_t *front)
{
  config_line_t *tmp;

  while (front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** Return the description for a given configuration variable, or NULL if no
 * description exists. */
static const char *
config_find_description(config_format_t *fmt, const char *name)
{
  int i;
  for (i=0; fmt->descriptions[i].name; ++i) {
    if (!strcasecmp(name, fmt->descriptions[i].name))
      return fmt->descriptions[i].description;
  }
  return NULL;
}

/** If <b>key</b> is a configuration option, return the corresponding
 * config_var_t.  Otherwise, if <b>key</b> is a non-standard abbreviation,
 * warn, and return the corresponding config_var_t.  Otherwise return NULL.
 */
static config_var_t *
config_find_option(config_format_t *fmt, const char *key)
{
  int i;
  size_t keylen = strlen(key);
  if (!keylen)
    return NULL; /* if they say "--" on the commandline, it's not an option */
  /* First, check for an exact (case-insensitive) match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strcasecmp(key, fmt->vars[i].name)) {
      return &fmt->vars[i];
    }
  }
  /* If none, check for an abbreviated match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strncasecmp(key, fmt->vars[i].name, keylen)) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ABBREVIATION_DEPRECATED),key, fmt->vars[i].name);
      return &fmt->vars[i];
    }
  }
  /* Okay, unrecognized option */
  return NULL;
}

/** Return the number of option entries in <b>fmt</b>. */
static int
config_count_options(config_format_t *fmt)
{
  int i;
  for (i=0; fmt->vars[i].name; ++i)
    ;
  return i;
}

/*
 * Functions to assign config options.
 */

/** <b>c</b>-\>key is known to be a real key. Update <b>options</b>
 * with <b>c</b>-\>value and return 0, or return -1 if bad value.
 *
 * Called from config_assign_line() and option_reset().
 */
static int
config_assign_value(config_format_t *fmt, or_options_t *options,
                    config_line_t *c, unsigned char **msg)
{
  int i, ok;
  config_var_t *var;
  void *lvalue;

  CHECK(fmt, options);

  var = config_find_option(fmt, (char *)c->key);
  tor_assert(var);

  lvalue = STRUCT_VAR_P(options, var->var_offset);

  switch (var->type) {

  case CONFIG_TYPE_PORT:
    if (!strcasecmp((char *)c->value, "auto")) {
      *(int *)lvalue = CFG_AUTO_PORT;
      break;
    }
    /* fall through */

  case CONFIG_TYPE_UINT:
    if(c->value[0]=='-') i = -(int)tor_parse_long((char *)&c->value[1], 10, 0, INT_MAX, &ok, NULL);
    else i = (int)tor_parse_long((char *)c->value, 10, 0, var->type==CONFIG_TYPE_PORT ? 65535 : INT_MAX, &ok, NULL);
    if (!ok) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_INT),c->key, c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_INTERVAL: {
    i = config_parse_interval((char *)c->value, &ok);
    if (!ok) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_INTERVAL),c->key,c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;
  }

  case CONFIG_TYPE_MEMUNIT: {
    uint64_t u64 = config_parse_memunit((char *)c->value, &ok);
    if (!ok) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_VALUE),c->key,c->value);
      return -1;
    }
    *(uint64_t *)lvalue = u64;
    break;
  }

  case CONFIG_TYPE_BOOL:
    i = (int)tor_parse_long((char *)c->value, 10, 0, 1, &ok, NULL);
    if (!ok) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_BOOLEAN),c->key,c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_STRING:
  case CONFIG_TYPE_FILENAME:
    tor_free(*(char **)lvalue);
    *(char **)lvalue = tor_strdup((char *)c->value);
    break;

  case CONFIG_TYPE_DOUBLE:
    *(double *)lvalue = atof((char *)c->value);
    break;

  case CONFIG_TYPE_ISOTIME:
    if (parse_iso_time((char *)c->value, (time_t *)lvalue)) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_KEYWORD_TYPE),c->value,c->key);
      return -1;
    }
    break;

  case CONFIG_TYPE_ROUTERSET:
    if (*(routerset_t**)lvalue) {
      routerset_free(*(routerset_t**)lvalue);
    }
    *(routerset_t**)lvalue = routerset_new();
    if (routerset_parse(*(routerset_t**)lvalue, (char *)c->value, (char *)c->key)<0) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_EXIT_LIST),c->value,c->key);
      return -1;
    }
    break;

  case CONFIG_TYPE_CSV:
    if (*(smartlist_t**)lvalue) {
      SMARTLIST_FOREACH(*(smartlist_t**)lvalue, char *, cp, tor_free(cp));
      smartlist_clear(*(smartlist_t**)lvalue);
    } else {
      *(smartlist_t**)lvalue = smartlist_create();
    }

    smartlist_split_string(*(smartlist_t**)lvalue, (char *)c->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    break;

  case CONFIG_TYPE_LINELIST:
  case CONFIG_TYPE_LINELIST_S:
    config_line_append((config_line_t**)lvalue, (char *)c->key, (char *)c->value);
    break;
  case CONFIG_TYPE_OBSOLETE:
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OBSOLETE_OPTION),c->key);
    break;
  case CONFIG_TYPE_LINELIST_V:
    tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_VIRTUAL_OPTION_VALUE),c->key);
    return -1;
  default:
    tor_assert(0);
    break;
  }
  return 0;
}

/** If <b>c</b> is a syntactically valid configuration line, update
 * <b>options</b> with its value and return 0.  Otherwise return -1 for bad
 * key, -2 for bad value.
 *
 * If <b>clear_first</b> is set, clear the value first. Then if
 * <b>use_defaults</b> is set, set the value to the default.
 *
 * Called from config_assign().
 */
static int
config_assign_line(config_format_t *fmt, or_options_t *options,
                   config_line_t *c, int use_defaults,
                   int clear_first, bitarray_t *options_seen, unsigned char **msg)
{
  config_var_t *var;

  CHECK(fmt, options);

  var = config_find_option(fmt, (char *)c->key);
  if (!var) {
    if (fmt->extra) {
      void *lvalue = STRUCT_VAR_P(options, fmt->extra->var_offset);
      log_info(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_UNRECOGNIZED_OPTION),c->key);
      config_line_append((config_line_t**)lvalue, (char *)c->key, (char *)c->value);
      return 0;
    } else {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_UNKNOWN_OPTION),c->key);
      return 0;
    }
  }
  /* Put keyword into canonical case. */
  if (strcmp(var->name, (char *)c->key)) {
    tor_free(c->key);
    c->key = (unsigned char *)tor_strdup(var->name);
  }

  if (!strlen((char *)c->value)) {
    /* reset or clear it, then return */
    if (!clear_first) {
      if (var->type == CONFIG_TYPE_LINELIST ||
          var->type == CONFIG_TYPE_LINELIST_S) {
        /* We got an empty linelist from the torrc or commandline.
           As a special case, call this an error. Warn and ignore. */
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OPTION_WITH_NO_VALUE),c->key);
      } else { /* not already cleared */
        option_reset(fmt, options, var, use_defaults);
      }
    }
    return 0;
  }

  if (options_seen && (var->type != CONFIG_TYPE_LINELIST &&
                       var->type != CONFIG_TYPE_LINELIST_S)) {
    /* We're tracking which options we've seen, and this option is not
     * supposed to occur more than once. */
    int var_index = (int)(var - fmt->vars);
    if (bitarray_is_set(options_seen, var_index)) {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OPTION_SEEN),var->name);
    }
    bitarray_set(options_seen, var_index);
  }

  if (config_assign_value(fmt, options, c, msg) < 0)
    return -2;
  return 0;
}

/** Restore the option named <b>key</b> in options to its default value.
 * Called from config_assign(). */
static void
config_reset_line(config_format_t *fmt, or_options_t *options,
                  const char *key, int use_defaults)
{
  config_var_t *var;

  CHECK(fmt, options);

  var = config_find_option(fmt, key);
  if (!var)
    return; /* give error on next pass. */

  option_reset(fmt, options, var, use_defaults);
}

/** Return true iff key is a valid configuration option. */
int
option_is_recognized(const char *key)
{
  config_var_t *var = config_find_option(&options_format, key);
  return (var != NULL);
}

/** Return the canonical name of a configuration option, or NULL
 * if no such option exists. */
const char *
option_get_canonical_name(const char *key)
{
  config_var_t *var = config_find_option(&options_format, key);
  return var ? var->name : NULL;
}

/** Return a canonicalized list of the options assigned for key.
 */
config_line_t *
option_get_assignment(or_options_t *options, const char *key)
{
  return get_assigned_option(&options_format, options, key, 1);
}

/** Return true iff value needs to be quoted and escaped to be used in
 * a configuration file. */
static int
config_value_needs_escape(const char *value)
{
  if (*value == '\"')
    return 1;
  while (*value) {
    switch (*value)
    {
    case '\r':
    case '\n':
    case '[':
    case ';':
      /* Note: quotes and backspaces need special handling when we are using
       * quotes, not otherwise, so they don't trigger escaping on their
       * own. */
      return 1;
    default:
      if (!TOR_ISPRINT(*value))
        return 1;
    }
    ++value;
  }
  return 0;
}

/** Return a newly allocated deep copy of the lines in <b>inp</b>. */
static config_line_t *
config_lines_dup(const config_line_t *inp)
{
  config_line_t *result = NULL;
  config_line_t **next_out = &result;
  while (inp) {
    *next_out = tor_malloc(sizeof(config_line_t));
    (*next_out)->key = (unsigned char *)tor_strdup((char *)inp->key);
    (*next_out)->value = (unsigned char *)tor_strdup((char *)inp->value);
    inp = inp->next;
    next_out = &((*next_out)->next);
  }
  (*next_out) = NULL;
  return result;
}

/** Return newly allocated line or lines corresponding to <b>key</b> in the
 * configuration <b>options</b>.  If <b>escape_val</b> is true and a
 * value needs to be quoted before it's put in a config file, quote and
 * escape that value. Return NULL if no such key exists. */
static config_line_t *
get_assigned_option(config_format_t *fmt, void *options,
                    const char *key, int escape_val)
{
  config_var_t *var;
  const void *value;
  config_line_t *result;
  tor_assert(options && key);

  CHECK(fmt, options);

  var = config_find_option(fmt, key);
  if (!var) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_UNKNOWN_OPTION),key);
    return NULL;
  }
  value = STRUCT_VAR_P(options, var->var_offset);

  result = tor_malloc_zero(sizeof(config_line_t));
  result->key = (unsigned char *)tor_strdup(var->name);
  switch (var->type)
    {
    case CONFIG_TYPE_STRING:
    case CONFIG_TYPE_FILENAME:
      if (*(char**)value) {
        result->value = (unsigned char *)tor_strdup(*(char**)value);
      } else {
        tor_free(result->key);
        tor_free(result);
        return NULL;
      }
      break;
    case CONFIG_TYPE_ISOTIME:
      if (*(time_t*)value) {
        result->value = (unsigned char *)tor_malloc(ISO_TIME_LEN+1);
        format_iso_time((char *)result->value, *(time_t*)value);
      } else {
        tor_free(result->key);
        tor_free(result);
      }
      escape_val = 0; /* Can't need escape. */
      break;
    case CONFIG_TYPE_PORT:
      if (*(int*)value == CFG_AUTO_PORT) {
        result->value = (unsigned char *)tor_strdup("auto");
        escape_val = 0;
        break;
      }
      /* fall through */
    case CONFIG_TYPE_INTERVAL:
    case CONFIG_TYPE_UINT:
      /* This means every or_options_t uint or bool element
       * needs to be an int. Not, say, a uint16_t or char. */
      tor_asprintf(&result->value, "%d", *(int*)value);
      escape_val = 0; /* Can't need escape. */
      break;
    case CONFIG_TYPE_MEMUNIT:
      tor_asprintf(&result->value,U64_FORMAT,
                   U64_PRINTF_ARG(*(uint64_t*)value));
      escape_val = 0; /* Can't need escape. */
      break;
    case CONFIG_TYPE_DOUBLE:
      tor_asprintf(&result->value, "%f", *(double*)value);
      escape_val = 0; /* Can't need escape. */
      break;
    case CONFIG_TYPE_BOOL:
      result->value = (unsigned char *)tor_strdup(*(int*)value ? "1" : "0");
      escape_val = 0; /* Can't need escape. */
      break;
    case CONFIG_TYPE_ROUTERSET:
      result->value = (unsigned char *)routerset_to_string(*(routerset_t**)value);
      break;
    case CONFIG_TYPE_CSV:
      if (*(smartlist_t**)value)
        result->value =
          (unsigned char *)smartlist_join_strings(*(smartlist_t**)value, ",", 0, NULL);
      else
        result->value = (unsigned char *)tor_strdup("");
      break;
    case CONFIG_TYPE_OBSOLETE:
      log_fn(LOG_PROTOCOL_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OBSOLETE_OPTION_VALUE),key);
      tor_free(result->key);
      tor_free(result);
      return NULL;
    case CONFIG_TYPE_LINELIST_S:
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CANT_RETURN_LINELIST),key);
      tor_free(result->key);
      tor_free(result);
      return NULL;
    case CONFIG_TYPE_LINELIST:
    case CONFIG_TYPE_LINELIST_V:
      tor_free(result->key);
      tor_free(result);
      result = config_lines_dup(*(const config_line_t**)value);
      break;
    default:
      tor_free(result->key);
      tor_free(result);
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_OPTION_TYPE_UNKNOWN),var->type, key);
      return NULL;
    }

  if (escape_val) {
    config_line_t *line;
    for (line = result; line; line = line->next) {
      if (line->value && config_value_needs_escape((char *)line->value)) {
        unsigned char *newval = (unsigned char *)esc_for_log((char *)line->value);
        tor_free(line->value);
        line->value = newval;
      }
    }
  }

  return result;
}

/** Iterate through the linked list of requested options <b>list</b>.
 * For each item, convert as appropriate and assign to <b>options</b>.
 * If an item is unrecognized, set *msg and return -1 immediately,
 * else return 0 for success.
 *
 * If <b>clear_first</b>, interpret config options as replacing (not
 * extending) their previous values. If <b>clear_first</b> is set,
 * then <b>use_defaults</b> to decide if you set to defaults after
 * clearing, or make the value 0 or NULL.
 *
 * Here are the use cases:
 * 1. A non-empty AllowInvalid line in your torrc. Appends to current
 *    if linelist, replaces current if csv.
 * 2. An empty AllowInvalid line in your torrc. Should clear it.
 * 3. "RESETCONF AllowInvalid" sets it to default.
 * 4. "SETCONF AllowInvalid" makes it NULL.
 * 5. "SETCONF AllowInvalid=foo" clears it and sets it to "foo".
 *
 * Use_defaults   Clear_first
 *    0                0       "append"
 *    1                0       undefined, don't use
 *    0                1       "set to null first"
 *    1                1       "set to defaults first"
 * Return 0 on success, -1 on bad key, -2 on bad value.
 *
 * As an additional special case, if a LINELIST config option has
 * no value and clear_first is 0, then warn and ignore it.
 */

/*
There are three call cases for config_assign() currently.

Case one: Torrc entry
options_init_from_torrc() calls config_assign(0, 0)
  calls config_assign_line(0, 0).
    if value is empty, calls option_reset(0) and returns.
    calls config_assign_value(), appends.

Case two: setconf
options_trial_assign() calls config_assign(0, 1)
  calls config_reset_line(0)
    calls option_reset(0)
      calls option_clear().
  calls config_assign_line(0, 1).
    if value is empty, returns.
    calls config_assign_value(), appends.

Case three: resetconf
options_trial_assign() calls config_assign(1, 1)
  calls config_reset_line(1)
    calls option_reset(1)
      calls option_clear().
      calls config_assign_value(default)
  calls config_assign_line(1, 1).
    returns.
*/
static int
config_assign(config_format_t *fmt, void *options, config_line_t *list,
              int use_defaults, int clear_first, unsigned char **msg,const char *section)
{
  config_line_t *p;
  bitarray_t *options_seen;
  const int n_options = config_count_options(fmt);
  int i;
  int r=0;
  CHECK(fmt, options);
  if(section)
  {	while(list)
  	{	if(list->key[0]=='[')
		{	{ for(i=0;list->key[i]>32;i++); }
			if(i) list->key[i]=0;
			if(strcmp(section,(char *)list->key)==0)
			{	list=list->next;break;}
		}
		list=list->next;
	}
  }

  /* pass 1: normalize keys */
  for (p = list; p; p = p->next) {
    if(p->key[0]!='[')
    {
      const char *full = expand_abbrev(fmt, (char *)p->key, 0, 1);
      if (strcmp(full,(char *)p->key)) {
        tor_free(p->key);
        p->key = (unsigned char *)tor_strdup(full);
      }
    }
  }

  /* pass 2: if we're reading from a resetting source, clear all
   * mentioned config options, and maybe set to their defaults. */
  if (clear_first) {
    for (p = list; p; p = p->next)
      config_reset_line(fmt, options, (char *)p->key, use_defaults);
  }

  options_seen = bitarray_init_zero(n_options);
  /* pass 3: assign. */
  while (list) {
    if(section&&(list->key)&&(list->key[0]=='[')) break;
    if(list->key[0]!='[')
    {	r=config_assign_line(fmt, options, list, use_defaults,clear_first,options_seen,msg);
    	if(r)
	{	bitarray_free(options_seen);
		return r;
	}
    }
    list = list->next;
  }
  bitarray_free(options_seen);
  return r;
}

/** Try assigning <b>list</b> to the global options. You do this by duping
 * options, assigning list to the new one, then validating it. If it's
 * ok, then throw out the old one and stick with the new one. Else,
 * revert to old and return failure.  Return SETOPT_OK on success, or
 * a setopt_err_t on failure.
 *
 * If not success, point *<b>msg</b> to a newly allocated string describing
 * what went wrong.
 */
setopt_err_t
options_trial_assign(config_line_t *list, int use_defaults,
                     int clear_first, unsigned char **msg)
{
  int r;
  or_options_t *trial_options = options_dup(&options_format, get_options());

  if ((r=config_assign(&options_format, trial_options,
                       list, use_defaults, clear_first, msg,NULL)) < 0) {
//    config_free(&options_format, trial_options);
    return r;
  }

  if (options_validate(get_options(), trial_options, msg) < 0) {
    config_free(&options_format, trial_options);
    return SETOPT_ERR_PARSE; /*XXX make this a separate return value. */
  }

  if (set_options(trial_options, msg)<0) {
    config_free(&options_format, trial_options);
    return SETOPT_ERR_SETTING;
  }

  /* we liked it. put it in place. */
  return SETOPT_OK;
}

/** Reset config option <b>var</b> to 0, 0.0, NULL, or the equivalent.
 * Called from option_reset() and config_free(). */
static void
option_clear(config_format_t *fmt, or_options_t *options, config_var_t *var)
{
  void *lvalue = STRUCT_VAR_P(options, var->var_offset);
  (void)fmt; /* unused */
  switch (var->type) {
    case CONFIG_TYPE_STRING:
    case CONFIG_TYPE_FILENAME:
      tor_free(*(char**)lvalue);
      break;
    case CONFIG_TYPE_DOUBLE:
      *(double*)lvalue = 0.0;
      break;
    case CONFIG_TYPE_ISOTIME:
      *(time_t*)lvalue = 0;
      break;
    case CONFIG_TYPE_INTERVAL:
    case CONFIG_TYPE_UINT:
    case CONFIG_TYPE_PORT:
    case CONFIG_TYPE_BOOL:
      *(int*)lvalue = 0;
      break;
    case CONFIG_TYPE_MEMUNIT:
      *(uint64_t*)lvalue = 0;
      break;
    case CONFIG_TYPE_ROUTERSET:
      if (*(routerset_t**)lvalue) {
        routerset_free(*(routerset_t**)lvalue);
        *(routerset_t**)lvalue = NULL;
      }
      break;
    case CONFIG_TYPE_CSV:
      if (*(smartlist_t**)lvalue) {
        SMARTLIST_FOREACH(*(smartlist_t **)lvalue, char *, cp, tor_free(cp));
        smartlist_free(*(smartlist_t **)lvalue);
        *(smartlist_t **)lvalue = NULL;
      }
      break;
    case CONFIG_TYPE_LINELIST:
    case CONFIG_TYPE_LINELIST_S:
      config_free_lines(*(config_line_t **)lvalue);
      *(config_line_t **)lvalue = NULL;
      break;
    case CONFIG_TYPE_LINELIST_V:
      /* handled by linelist_s. */
      break;
    case CONFIG_TYPE_OBSOLETE:
      break;
  }
}

/** Clear the option indexed by <b>var</b> in <b>options</b>. Then if
 * <b>use_defaults</b>, set it to its default value.
 * Called by config_init() and option_reset_line() and option_assign_line(). */
static void
option_reset(config_format_t *fmt, or_options_t *options,
             config_var_t *var, int use_defaults)
{
  config_line_t *c;
  unsigned char *msg = NULL;
  CHECK(fmt, options);
  option_clear(fmt, options, var); /* clear it first */
  if (!use_defaults)
    return; /* all done */
  if (var->initvalue) {
    c = tor_malloc_zero(sizeof(config_line_t));
    c->key = (unsigned char *)tor_strdup(var->name);
    c->value = (unsigned char *)tor_strdup(var->initvalue);
    if (config_assign_value(fmt, options, c, &msg) < 0) {
      log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_DEFAULT_FAILED),msg);
      tor_free(msg); /* if this happens it's a bug */
    }
    config_free_lines(c);
  }
}


/** Print all non-obsolete torrc options. */
static void
list_torrc_options(void)
{
  int i;
  smartlist_t *lines = smartlist_create();
  for (i = 0; _option_vars[i].name; ++i) {
    config_var_t *var = &_option_vars[i];
    const char *desc;
    if (var->type == CONFIG_TYPE_OBSOLETE ||
        var->type == CONFIG_TYPE_LINELIST_V)
      continue;
    desc = config_find_description(&options_format, var->name);
    printf("%s\r\n", var->name);
    if (desc) {
      wrap_string(lines, desc, 76, "    ", "    ");
      SMARTLIST_FOREACH(lines, char *, cp, {
          printf("%s", cp);
          tor_free(cp);
        });
      smartlist_clear(lines);
    }
  }
  smartlist_free(lines);
}

/** Last value actually set by resolve_my_address. */
static uint32_t last_resolved_addr = 0;
/**
 * Based on <b>options-\>Address</b>, guess our public IP address and put it
 * (in host order) into *<b>addr_out</b>. If <b>hostname_out</b> is provided,
 * set *<b>hostname_out</b> to a new string holding the hostname we used to
 * get the address. Return 0 if all is well, or -1 if we can't find a suitable
 * public IP address.
 */
int
resolve_my_address(int warn_severity, or_options_t *options,
                   uint32_t *addr_out, char **hostname_out)
{
  struct in_addr in;
  struct hostent *rent;
  char hostname[256];
  int explicit_ip=1;
  int explicit_hostname=1;
  int from_interface=0;
  char tmpbuf[INET_NTOA_BUF_LEN];
  const char *address = options->Address;
  int notice_severity = warn_severity <= LOG_NOTICE ?
                          LOG_NOTICE : warn_severity;

  tor_assert(addr_out);

  if (address && *address) {
    strlcpy(hostname, address, sizeof(hostname));
  } else { /* then we need to guess our address */
    explicit_ip = 0; /* it's implicit */
    explicit_hostname = 0; /* it's implicit */

    if (gethostname(hostname, sizeof(hostname)) < 0) {
      log_fn(warn_severity, LD_NET,get_lang_str(LANG_LOG_CONFIG_HOSTNAME_ERROR));
      return -1;
    }
    log_debug(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_HOSTNAME_OK),hostname);
  }

  /* now we know hostname. resolve it and keep only the IP address */

  if (tor_inet_aton(hostname, &in) == 0) {
    /* then we have to resolve it */
    explicit_ip = 0;
    rent = (struct hostent *)gethostbyname(hostname);
    if (!rent) {
      uint32_t interface_ip;

      if (explicit_hostname) {
        log_fn(warn_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_LOCAL_ADDR_RESOLVE_FAILED),hostname);
        return -1;
      }
      log_fn(notice_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_GUESSED_ADDR_RESOLVE_FAILED),hostname);
      if (get_interface_address(warn_severity, &interface_ip)) {
        log_fn(warn_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_COULD_NOT_GET_LOCAL_IP));
        return -1;
      }
      from_interface = 1;
      in.s_addr = htonl(interface_ip);
      tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
      log_fn(notice_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_GOT_LOCAL_IP),tmpbuf);
      strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
    } else {
      tor_assert(rent->h_length == 4);
      memcpy(&in.s_addr, rent->h_addr, rent->h_length);

      if (!explicit_hostname &&
          is_internal_IP(ntohl(in.s_addr), 0)) {
        uint32_t interface_ip;

        tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
        log_fn(notice_severity,LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_LOCAL_IP_PRIVATE_ADDR),hostname,tmpbuf);

        if (get_interface_address(warn_severity, &interface_ip)) {
          log_fn(warn_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_COULD_NOT_GET_LOCAL_IP_2));
        } else if (is_internal_IP(interface_ip, 0)) {
          struct in_addr in2;
          in2.s_addr = htonl(interface_ip);
          tor_inet_ntoa(&in2,tmpbuf,sizeof(tmpbuf));
          log_fn(notice_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_INTERFACE_IP_PRIVATE),tmpbuf);
        } else {
          from_interface = 1;
          in.s_addr = htonl(interface_ip);
          tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
          log_fn(notice_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_GOT_LOCAL_IP),tmpbuf);
          strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
        }
      }
    }
  }

  tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
  if (is_internal_IP(ntohl(in.s_addr), 0)) {
    /* make sure we're ok with publishing an internal IP */
    if (!options->DirServers && !options->AlternateDirAuthority) {
      /* if they are using the default dirservers, disallow internal IPs
       * always. */
      log_fn(warn_severity, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ADDR_RESOLVES_TO_PRIVATE_IP),hostname,tmpbuf);
      return -1;
    }
    if (!explicit_ip) {
      /* even if they've set their own dirservers, require an explicit IP if
       * they're using an internal address. */
      log_fn(warn_severity,LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ADDR_RESOLVES_TO_PRIVATE_IP_2),hostname,tmpbuf);
      return -1;
    }
  }

  log_debug(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_RESOLVED_ADDRESS_TO),tmpbuf);
  *addr_out = ntohl(in.s_addr);
  if (last_resolved_addr && last_resolved_addr != *addr_out) {
    /* Leave this as a notice, regardless of the requested severity,
     * at least until dynamic IP address support becomes bulletproof. */
    log_notice(LD_NET,get_lang_str(LANG_LOG_CONFIG_YOUR_IP_CHANGED),tmpbuf);
    ip_address_changed(0);
  }
  if (last_resolved_addr != *addr_out) {
    const char *method;
    const char *h = hostname;
    if (explicit_ip) {
      method = "CONFIGURED";
      h = NULL;
    } else if (explicit_hostname) {
      method = "RESOLVED";
    } else if (from_interface) {
      method = "INTERFACE";
      h = NULL;
    } else {
      method = "GETHOSTNAME";
    }
    control_event_server_status(LOG_NOTICE,
                                "EXTERNAL_ADDRESS ADDRESS=%s METHOD=%s %s%s",
                                tmpbuf, method, h?"HOSTNAME=":"", h);
  }
  last_resolved_addr = *addr_out;
  if (hostname_out)
    *hostname_out = tor_strdup(hostname);
  return 0;
}

/** Return true iff <b>addr</b> is judged to be on the same network as us, or
 * on a private network.
 */
int
is_local_addr(const tor_addr_t *addr)
{
  if (tor_addr_is_internal(addr, 0))
    return 1;
  /* Check whether ip is on the same /24 as we are. */
  if (get_options()->EnforceDistinctSubnets == 0)
    return 0;
  if (tor_addr_family(addr) == AF_INET) {
    /*XXXX022 IP6 what corresponds to an /24? */
    uint32_t ip = tor_addr_to_ipv4h(addr);

    /* It's possible that this next check will hit before the first time
     * resolve_my_address actually succeeds.  (For clients, it is likely that
     * resolve_my_address will never be called at all).  In those cases,
     * last_resolved_addr will be 0, and so checking to see whether ip is on
     * the same /24 as last_resolved_addr will be the same as checking whether
     * it was on net 0, which is already done by is_internal_IP.
     */
    if ((last_resolved_addr & 0xffffff00ul) == (ip & 0xffffff00ul))
      return 1;
  }
  return 0;
}

/** Release storage held by <b>options</b>. */
static void
config_free(config_format_t *fmt, void *options)
{
  int i;

  if (!options)
    return;

  tor_assert(fmt);

  for (i=0; fmt->vars[i].name; ++i)
    option_clear(fmt, options, &(fmt->vars[i]));
  if (fmt->extra) {
    config_line_t **linep = STRUCT_VAR_P(options, fmt->extra->var_offset);
    config_free_lines(*linep);
    *linep = NULL;
  }
  tor_free(options);
}

/** Return true iff a and b contain identical keys and values in identical
 * order. */
static int
config_lines_eq(config_line_t *a, config_line_t *b)
{
  while (a && b) {
    if (strcasecmp((char *)a->key, (char *)b->key) || strcmp((char *)a->value, (char *)b->value))
      return 0;
    a = a->next;
    b = b->next;
  }
  if (a || b)
    return 0;
  return 1;
}

/** Return true iff the option <b>name</b> has the same value in <b>o1</b>
 * and <b>o2</b>.  Must not be called for LINELIST_S or OBSOLETE options.
 */
static int
option_is_same(config_format_t *fmt,
               or_options_t *o1, or_options_t *o2, const char *name)
{
  config_line_t *c1, *c2;
  int r = 1;
  CHECK(fmt, o1);
  CHECK(fmt, o2);

  c1 = get_assigned_option(fmt, o1, name, 0);
  c2 = get_assigned_option(fmt, o2, name, 0);
  r = config_lines_eq(c1, c2);
  config_free_lines(c1);
  config_free_lines(c2);
  return r;
}

/** Copy storage held by <b>old</b> into a new or_options_t and return it. */
static or_options_t *
options_dup(config_format_t *fmt, or_options_t *old)
{
  or_options_t *newopts;
  int i;
  config_line_t *line;

  newopts = config_alloc(fmt);
  for (i=0; fmt->vars[i].name; ++i) {
    if (fmt->vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    if (fmt->vars[i].type == CONFIG_TYPE_OBSOLETE)
      continue;
    line = get_assigned_option(fmt, old, fmt->vars[i].name, 0);
    if (line) {
      unsigned char *msg = NULL;
      if (config_assign(fmt, newopts, line, 0, 0, &msg,NULL) < 0) {
        log_err(LD_BUG,get_lang_str(LANG_LOG_CONFIG_CONFIG_GET_ASSIGNED_OPTION_ERROR),msg);
        tor_free(msg);
        tor_assert(0);
      }
    }
    config_free_lines(line);
  }
  return newopts;
}

/** Return a new empty or_options_t.  Used for testing. */
or_options_t *
options_new(void)
{
  return config_alloc(&options_format);
}

/** Set <b>options</b> to hold reasonable defaults for most options.
 * Each option defaults to zero. */
void
options_init(or_options_t *options)
{
  config_init(&options_format, options);
}

/** Set all vars in the configuration object <b>options</b> to their default
 * values. */
static void
config_init(config_format_t *fmt, void *options)
{
  int i;
  config_var_t *var;
  CHECK(fmt, options);

  for (i=0; fmt->vars[i].name; ++i) {
    var = &fmt->vars[i];
    if (!var->initvalue)
      continue; /* defaults to NULL or 0 */
    option_reset(fmt, options, var, 1);
  }
}

/** Allocate and return a new string holding the written-out values of the vars
 * in 'options'.  If 'minimal', do not write out any default-valued vars.
 * Else, if comment_defaults, write default values as comments.
 */
static char *
config_dump(config_format_t *fmt, void *options, int minimal,
            int comment_defaults)
{
  smartlist_t *elements;
  or_options_t *defaults;
  config_line_t *line, *assigned;
  char *result;
  int i;
  const char *desc;
  char *msg = NULL;

  defaults = config_alloc(fmt);
  config_init(fmt, defaults);

  /* XXX use a 1 here so we don't add a new log line while dumping */
  if (fmt->validate_fn(NULL,defaults,&msg) < 0) {
    log_err(LD_BUG,get_lang_str(LANG_LOG_CONFIG_DEFAULT_CONFIG_VALIDATION_FAILED));
    tor_free(msg);
    tor_assert(0);
  }

  elements = smartlist_create();
  for (i=0; fmt->vars[i].name; ++i) {
    int comment_option = 0;
    if (fmt->vars[i].type == CONFIG_TYPE_OBSOLETE ||
        fmt->vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    /* Don't save 'hidden' control variables. */
//    if (!strcmpstart(fmt->vars[i].name, "__"))
//      continue;
    if (minimal && option_is_same(fmt, options, defaults, fmt->vars[i].name))
      continue;
    else if (comment_defaults &&
             option_is_same(fmt, options, defaults, fmt->vars[i].name))
      comment_option = 1;

    desc = config_find_description(fmt, fmt->vars[i].name);
    line = assigned = get_assigned_option(fmt, options, fmt->vars[i].name, 1);

    if (line && desc) {
      /* Only dump the description if there's something to describe. */
      wrap_string(elements, desc, 78, "; ", "; ");
    }

    for (; line; line = line->next) {
      size_t len = strlen((char *)line->key) + strlen((char *)line->value) + 10;
      char *tmp;
      tmp = tor_malloc(len);
      if (tor_snprintf(tmp, len, "%s%s%s%s\r\n\r\n",
                       comment_option ? "; " : "",
                       line->key,comment_option ?" ":"=", line->value)<0) {
        log_err(LD_BUG,get_lang_str(LANG_LOG_CONFIG_INTERNAL_ERROR_WRITING_OPTION_VALUE));
        tor_assert(0);
      }
      smartlist_add(elements, tmp);
    }
    config_free_lines(assigned);
  }

  if (fmt->extra) {
    line = *(config_line_t**)STRUCT_VAR_P(options, fmt->extra->var_offset);
    for (; line; line = line->next) {
      size_t len = strlen((char *)line->key) + strlen((char *)line->value) + 5;
      char *tmp;
      tmp = tor_malloc(len);
      if (tor_snprintf(tmp, len, "%s=%s\r\n\r\n", line->key, line->value)<0) {
        log_err(LD_BUG,get_lang_str(LANG_LOG_CONFIG_INTERNAL_ERROR_WRITING_OPTION_VALUE_2),line->key);
        tor_assert(0);
      }
      smartlist_add(elements, tmp);
    }
  }

  result = smartlist_join_strings(elements, "", 0, NULL);
  SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
  smartlist_free(elements);
  config_free(fmt, defaults);

  return result;
}

/** Return a string containing a possible configuration file that would give
 * the configuration in <b>options</b>.  If <b>minimal</b> is true, do not
 * include options that are the same as Tor's defaults.
 */
char *
options_dump(or_options_t *options, int minimal)
{
  return config_dump(&options_format, options, minimal, 0);
}

/** Return 0 if every element of sl is a string holding a decimal
 * representation of a port number, or if sl is NULL.
 * Otherwise set *msg and return -1. */
static int validate_ports_csv(smartlist_t *sl, const char *name, unsigned char **msg)
{
  int i;
  tor_assert(name);

  if (!sl)
    return 0;

  SMARTLIST_FOREACH(sl, const char *, cp,
  {
    i = atoi(cp);
    if (i < 1 || i > 65535) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_PORT),cp,name);
      return -1;
    }
  });
  return 0;
}

/** Parse an authority type from <b>options</b>-\>PublishServerDescriptor
 * and write it to <b>options</b>-\>_PublishServerDescriptor. Treat "1"
 * as "v2,v3" unless BridgeRelay is 1, in which case treat it as "bridge".
 * Treat "0" as "".
 * Return 0 on success or -1 if not a recognized authority type (in which
 * case the value of _PublishServerDescriptor is undefined). */
int compute_publishserverdescriptor(or_options_t *options)
{
  smartlist_t *list = options->PublishServerDescriptor;
  authority_type_t *auth = &options->_PublishServerDescriptor;
  *auth = NO_AUTHORITY;
  if (!list) /* empty list, answer is none */
    return 0;
  SMARTLIST_FOREACH(list, const char *, string, {
    if (!strcasecmp(string, "v1"))
      *auth |= V1_AUTHORITY;
    else if (!strcmp(string, "1"))
      if (options->BridgeRelay)
        *auth |= BRIDGE_AUTHORITY;
      else
        *auth |= V2_AUTHORITY | V3_AUTHORITY;
    else if (!strcasecmp(string, "v2"))
      *auth |= V2_AUTHORITY;
    else if (!strcasecmp(string, "v3"))
      *auth |= V3_AUTHORITY;
    else if (!strcasecmp(string, "bridge"))
      *auth |= BRIDGE_AUTHORITY;
    else if (!strcasecmp(string, "hidserv"))
      *auth |= HIDSERV_AUTHORITY;
    else if (!strcasecmp(string, "") || !strcmp(string, "0"))
      /* no authority */;
    else
      return -1;
    });
  return 0;
}

/** Lowest allowable value for RendPostPeriod; if this is too low, hidden
 * services can overload the directory system. */
//#define MIN_REND_POST_PERIOD (10*60)

/** Highest allowable value for RendPostPeriod. */
//#define MAX_DIR_PERIOD (MIN_ONION_KEY_LIFETIME/2)

/** Lowest allowable value for MaxCircuitDirtiness; if this is too low, Tor
 * will generate too many circuits and potentially overload the network. */
#define MIN_MAX_CIRCUIT_DIRTINESS 10

/** Return 0 if every setting in <b>options</b> is reasonable, and a
 * permissible transition from <b>old_options</b>. Else return -1.
 * Should have no side effects, except for normalizing the contents of
 * <b>options</b>.
 *
 * On error, tor_strdup an error explanation into *<b>msg</b>.
 *
 * XXX
 * If <b>from_setconf</b>, we were called by the controller, and our
 * Log line should stay empty. If it's 0, then give us a default log
 * if there are no logs defined.
 */
static int options_validate(or_options_t *old_options, or_options_t *options, unsigned char **msg)
{
//	return 0;
  int i;
  config_line_t *cl;
#define REJECT(arg) \
  STMT_BEGIN *msg = (unsigned char *)tor_strdup(arg); return 0; STMT_END
#define COMPLAIN(arg) STMT_BEGIN log(LOG_WARN, LD_CONFIG, arg); STMT_END

  tor_assert(msg);
  *msg = NULL;

/*  if (options->ORPort == 0 && options->ORListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_ORLISTEN_WITHOUT_ORPORT));*/

  if (options->DirPort == 0 && options->DirListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_DIRLISTENADDRESS_WITHOUT_DIRPORT));

  if (options->DNSPort == 0 && options->DNSListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_DNSLISTENADDRESS_WITHOUT_DNSPORT));

  if (options->OwningControllerProcess) {
    const char *validate_pspec_msg = NULL;
    if (tor_validate_process_specifier(options->OwningControllerProcess,
                                       &validate_pspec_msg)) {
      tor_asprintf(msg, get_lang_str(LANG_LOG_CONFIG_BAD_OWNINGCONTROLLERPROCESS),
                   validate_pspec_msg);
      return -1;
    }
  }

  if (options->ControlPort == 0 && options->ControlListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_CONTROLLISTENADDRESS_WITHOUT_CONTROLPORT));

  if (options->TransPort == 0 && options->TransListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_TRANSLISTENADDRESS_WITHOUT_TRANSPORT));

  if (options->NatdPort == 0 && options->NatdListenAddress != NULL)
    REJECT(get_lang_str(LANG_LOG_CONFIG_NATDLISTENADDRESS_WITHOUT_NATDPORT));

  /* Don't gripe about SocksPort 0 with SocksListenAddress set; a standard
   * configuration does this. */

  for (i = 0; i < 3; ++i) {
    int is_socks = i==0;
    int is_trans = i==1;
    config_line_t *line, *opt, *old;
    const char *tp;
    if (is_socks) {
      opt = options->SocksListenAddress;
      old = old_options ? old_options->SocksListenAddress : NULL;
      tp = "SOCKS proxy";
    } else if (is_trans) {
      opt = options->TransListenAddress;
      old = old_options ? old_options->TransListenAddress : NULL;
      tp = "transparent proxy";
    } else {
      opt = options->NatdListenAddress;
      old = old_options ? old_options->NatdListenAddress : NULL;
      tp = "natd proxy";
    }

    for (line = opt; line; line = line->next) {
      char *address = NULL;
      uint16_t port;
      uint32_t addr;
      if (parse_addr_port(LOG_WARN, (char *)line->value, &address, &addr, &port)<0)
        continue; /* We'll warn about this later. */
      if (!is_internal_IP(addr, 1) &&
          (!old_options || !config_lines_eq(old, opt))) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_YOU_SPECIFIED_A_PUBLIC_ADDRESS),address,tp,tp);
      }
      tor_free(address);
    }
  }

#ifndef int3
  if (options->Nickname == NULL) {
    if (server_mode(options)) {
      options->Nickname = tor_strdup(UNNAMED_ROUTER_NICKNAME);
      log_notice(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DEFAULT_NICKNAME_CHOSEN),options->Nickname);
    }
  } else {
    if (!is_legal_nickname(options->Nickname)) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_NICKNAME),options->Nickname);
      return -1;
    }
  }
#endif

#ifdef int3
  if (!options->ContactInfo)
  	options->ContactInfo=tor_strdup("Random Person <nobody AT example dot com>");
#endif

  if (options->NoPublish) {
    log(LOG_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_NOPUBLISH_IS_OBSOLETE));
    SMARTLIST_FOREACH(options->PublishServerDescriptor, char *, s,
                      tor_free(s));
    smartlist_clear(options->PublishServerDescriptor);
  }

  if (authdir_mode(options)) {
    /* confirm that our address isn't broken, so we can complain now */
    uint32_t tmp;
    if (resolve_my_address(LOG_WARN, options, &tmp, NULL) < 0)
      REJECT(get_lang_str(LANG_LOG_CONFIG_FAILED_TO_RESOLVE_LOCAL_ADDRESS));
  }

  if (strcmp(options->RefuseUnknownExits, "0") &&
      strcmp(options->RefuseUnknownExits, "1") &&
      strcmp(options->RefuseUnknownExits, "auto")) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_REFUSEUNKNOWNEXITS));
  }

  if (options->SocksPort == 0 && options->TransPort == 0 &&
      options->NatdPort == 0 && options->ORPort == 0 &&
      options->DNSPort == 0 && !options->RendConfigLines)
    log(LOG_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_NO_PORTS_DEFINED));

#ifndef USE_TRANSPARENT
  if (options->TransPort || options->TransListenAddress)
    REJECT(get_lang_str(LANG_LOG_CONFIG_TRANSPORT_DISABLED));
#endif

  if (options->_ExcludeExitNodesUnion)	routerset_free(options->_ExcludeExitNodesUnion);
  if (options->ExcludeExitNodes || options->ExcludeNodes) {
    options->_ExcludeExitNodesUnion = routerset_new();
    routerset_union(options->_ExcludeExitNodesUnion,options->ExcludeExitNodes);
    routerset_union(options->_ExcludeExitNodesUnion,options->ExcludeNodes);
  }

  if (options->StrictExitNodes &&
      (!options->ExitNodes) &&
      (!old_options ||
       (old_options->StrictExitNodes != options->StrictExitNodes) ||
       (!routerset_equal(old_options->ExitNodes,options->ExitNodes))))
    COMPLAIN(get_lang_str(LANG_LOG_CONFIG_STRICTEXITNODES_WITHOUT_EXITNODES));

  if (options->StrictEntryNodes &&
      (!options->EntryNodes) &&
      (!old_options ||
       (old_options->StrictEntryNodes != options->StrictEntryNodes) ||
       (!routerset_equal(old_options->EntryNodes,options->EntryNodes))))
    COMPLAIN(get_lang_str(LANG_LOG_CONFIG_STRICTENTRYNODES_WITHOUT_ENTRYNODES));

  if (options->EntryNodes && !routerset_is_list(options->EntryNodes)) {
    /* XXXX fix this; see entry_guards_prepend_from_config(). */
    REJECT(get_lang_str(LANG_LOG_CONFIG_IPS_IN_ENTRYNODES));
  }

  if (options->AuthoritativeDir) {
    if (!options->ContactInfo)
      REJECT(get_lang_str(LANG_LOG_CONFIG_AUTH_DIR_MUST_SET_CONTACTINFO));
    if (options->V1AuthoritativeDir && !options->RecommendedVersions)
      REJECT(get_lang_str(LANG_LOG_CONFIG_AUTH_DIR_WITHOUT_RECOMMENDEDVERSIONS));
    if (!options->RecommendedClientVersions)
      options->RecommendedClientVersions =
        config_lines_dup(options->RecommendedVersions);
    if (!options->RecommendedServerVersions)
      options->RecommendedServerVersions =
        config_lines_dup(options->RecommendedVersions);
    if (options->VersioningAuthoritativeDir &&
        (!options->RecommendedClientVersions ||
         !options->RecommendedServerVersions))
      REJECT(get_lang_str(LANG_LOG_CONFIG_VERSIONING_AUTH_WITHOUT_RECOMMENDEDVERSIONS));
    if (options->UseEntryGuards) {
      log_info(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIR_SERVERS_CANT_SET_USEENTRYGUARDS));
      options->UseEntryGuards = 0;
    }
    if (!options->DownloadExtraInfo && authdir_mode_any_main(options)) {
      log_info(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_SETTING_DOWNLOADEXTRAINFO));
      options->DownloadExtraInfo = 1;
    }
    if (!(options->BridgeAuthoritativeDir || options->HSAuthoritativeDir ||
          options->V1AuthoritativeDir || options->V2AuthoritativeDir ||
          options->V3AuthoritativeDir))
      REJECT(get_lang_str(LANG_LOG_CONFIG_AUTHDIR_WITHOUT_TYPE));
    /* If we have a v3bandwidthsfile and it's broken, complain on startup */
    if (options->V3BandwidthsFile && !old_options) {
      dirserv_read_measured_bandwidths(options->V3BandwidthsFile, NULL);
    }
  }

  if (options->AuthoritativeDir && !options->DirPort)
    REJECT(get_lang_str(LANG_LOG_CONFIG_AUTH_DIR_WITHOUT_DIRPORT));

  if (options->AuthoritativeDir && !options->ORPort)
    REJECT(get_lang_str(LANG_LOG_CONFIG_AUTH_DIR_WITHOUT_ORPORT));

  if (options->AuthoritativeDir && options->ClientOnly)
    REJECT(get_lang_str(LANG_LOG_CONFIG_AUTH_DIR_WITH_CLIENTONLY));

  if (validate_ports_csv(options->FirewallPorts, "FirewallPorts", msg) < 0)
    return -1;

  if (validate_ports_csv(options->LongLivedPorts, "LongLivedPorts", msg) < 0)
    return -1;

  if (validate_ports_csv(options->RejectPlaintextPorts,
                         "RejectPlaintextPorts", msg) < 0)
    return -1;

  if (validate_ports_csv(options->WarnPlaintextPorts,
                         "WarnPlaintextPorts", msg) < 0)
    return -1;

  if (options->FascistFirewall && !options->ReachableAddresses) {
    if (options->FirewallPorts && smartlist_len(options->FirewallPorts)) {
      /* We already have firewall ports set, so migrate them to
       * ReachableAddresses, which will set ReachableORAddresses and
       * ReachableDirAddresses if they aren't set explicitly. */
      smartlist_t *instead = smartlist_create();
      config_line_t *new_line = tor_malloc_zero(sizeof(config_line_t));
      new_line->key = (unsigned char *)tor_strdup("ReachableAddresses");
      /* If we're configured with the old format, we need to prepend some
       * open ports. */
      SMARTLIST_FOREACH(options->FirewallPorts, const char *, portno,
      {
        int p = atoi(portno);
        char *s;
        if (p<0) continue;
        s = tor_malloc(16);
        tor_snprintf(s, 16, "*:%d", p);
        smartlist_add(instead, s);
      });
      new_line->value = (unsigned char *)smartlist_join_strings(instead,",",0,NULL);
      /* These have been deprecated since 0.1.1.5-alpha-cvs */
      log(LOG_NOTICE, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONVERTING_FIREWALL_OPTIONS),new_line->value);
      options->ReachableAddresses = new_line;
      SMARTLIST_FOREACH(instead, char *, cp, tor_free(cp));
      smartlist_free(instead);
    } else {
      /* We do not have FirewallPorts set, so add 80 to
       * ReachableDirAddresses, and 443 to ReachableORAddresses. */
    }
  }

    config_line_t **linep =&options->ReachableAddresses;
    if (*linep)
    {
    /* We need to end with a reject *:*, not an implicit accept *:* */
    for (;;) {
      if (!strcmp((char *)(*linep)->value, "reject *:*")) /* already there */
        break;
      linep = &((*linep)->next);
      if (!*linep) {
        *linep = tor_malloc_zero(sizeof(config_line_t));
        (*linep)->key = (unsigned char *)tor_strdup("ReachableAddresses");
        (*linep)->value = (unsigned char *)tor_strdup("reject *:*");
        break;
      }
    }
    }

  if ((options->ReachableAddresses) &&
      server_mode(options))
    REJECT(get_lang_str(LANG_LOG_CONFIG_SERVER_WITH_FASCIST_FIREWALL));

  if (options->UseBridges && server_mode(options))
    REJECT(get_lang_str(LANG_LOG_CONFIG_SERVER_WITH_USEBRIDGES));


  if (compute_publishserverdescriptor(options) < 0) {
    tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_PUBLISHSERVERDESCRIPTOR_INVALID));
    return -1;
  }

  if (options->BridgeRelay && options->DirPort) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DISABLING_DIRPORT));
    options->DirPort = 0;
  }

  if (options->MinUptimeHidServDirectoryV2 < 0) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_MINUPTIME_MUST_BE_AT_LEAST_0));
    options->MinUptimeHidServDirectoryV2 = 0;
  }
/*
  if (options->RendPostPeriod < MIN_REND_POST_PERIOD) {
    log(LOG_WARN,LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_RENDPOSTPERIOD_TOO_SHORT), MIN_REND_POST_PERIOD);
    options->RendPostPeriod = MIN_REND_POST_PERIOD;
  }

  if (options->RendPostPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_RENDPOSTPERIOD_TOO_LARGE),MAX_DIR_PERIOD);
    options->RendPostPeriod = MAX_DIR_PERIOD;
  }
*/
#ifndef int3
  if (options->CircuitBuildTimeout < MIN_CIRCUIT_BUILD_TIMEOUT) {
    log(LOG_WARN,LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CIRCUITBUILDTIMEOUT_TOO_SHORT),MIN_CIRCUIT_BUILD_TIMEOUT);
    options->CircuitBuildTimeout = MIN_CIRCUIT_BUILD_TIMEOUT;
  }
#endif

#ifndef int3
  if (options->MaxCircuitDirtiness < MIN_MAX_CIRCUIT_DIRTINESS) {
    log(LOG_WARN,LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_MAXCIRCUITDIRTINESS_TOO_SHORT),MIN_MAX_CIRCUIT_DIRTINESS);
    options->MaxCircuitDirtiness = MIN_MAX_CIRCUIT_DIRTINESS;
  }
#endif

  if (options->KeepalivePeriod < 1)
    REJECT(get_lang_str(LANG_LOG_CONFIG_KEEPALIVE_NEGATIVE));

  if (options->RelayBandwidthRate && !options->RelayBandwidthBurst)
    options->RelayBandwidthBurst = options->RelayBandwidthRate;
  if (options->RelayBandwidthBurst && !options->RelayBandwidthRate)
    options->RelayBandwidthRate = options->RelayBandwidthBurst;

  if (server_mode(options)) {
    if (options->BandwidthRate < ROUTER_REQUIRED_MIN_BANDWIDTH) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_BANDWIDTHRATE_TOO_LOW),(int)options->BandwidthRate,ROUTER_REQUIRED_MIN_BANDWIDTH*2);
      return -1;
    } else if (options->MaxAdvertisedBandwidth <
               ROUTER_REQUIRED_MIN_BANDWIDTH) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_MAXADVERTISEDBANDWIDTH_TOO_LOW),(int)options->MaxAdvertisedBandwidth,ROUTER_REQUIRED_MIN_BANDWIDTH);
      return -1;
    }
    if (options->RelayBandwidthRate &&
      options->RelayBandwidthRate < ROUTER_REQUIRED_MIN_BANDWIDTH) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_RELAYBANDWIDTHRATE_TOO_LOW),(int)options->RelayBandwidthRate,ROUTER_REQUIRED_MIN_BANDWIDTH);
      return -1;
    }
  }

  if (options->RelayBandwidthRate > options->RelayBandwidthBurst)
    REJECT(get_lang_str(LANG_LOG_CONFIG_RELAYBANDWIDTHBURST_LESS_THAN_RELAYBANDWIDTHRATE));

  if (options->BandwidthRate > options->BandwidthBurst)
    REJECT(get_lang_str(LANG_LOG_CONFIG_BANDWIDTHBURST_LESS_THAN_BANDWIDTHRATE));

  /* if they set relaybandwidth* really high but left bandwidth*
   * at the default, raise the defaults. */
  if (options->RelayBandwidthRate > options->BandwidthRate)
    options->BandwidthRate = options->RelayBandwidthRate;
  if (options->RelayBandwidthBurst > options->BandwidthBurst)
    options->BandwidthBurst = options->RelayBandwidthBurst;

  if (accounting_parse_options(options, 1)<0)
    REJECT(get_lang_str(LANG_LOG_CONFIG_ACCOUNTING_PARSE_FAILED));

  if (options->DirProxy) { /* parse it now */
    if (tor_addr_port_parse(options->DirProxy,&options->DirProxyAddr, &options->DirProxyPort) < 0)
      REJECT(get_lang_str(LANG_LOG_CONFIG_HTTPPROXY_PARSE_FAILED));
    if (options->DirProxyPort == 0) { /* give it a default */
      options->DirProxyPort = 80;
    }
  }

  if (options->DirProxyAuthenticator) {
    if (strlen(options->DirProxyAuthenticator) >= 512)
      REJECT(get_lang_str(LANG_LOG_CONFIG_HTTPPROXYAUTHENTICATOR_TOO_LONG));
  }

	if(options->ORProxy)	/* parse it now */
	{	if(tor_addr_port_parse(options->ORProxy,&options->ORProxyAddr, &options->ORProxyPort) <0)
			REJECT(get_lang_str(LANG_LOG_CONFIG_HTTPSPROXY_PARSE_FAILED));
		if(options->ORProxyPort == 0)	/* give it a default */
			options->ORProxyPort = 443;
	}
	if(options->ORProxyAuthenticator)
	{	if(strlen(options->ORProxyAuthenticator) >= 512)
			REJECT(get_lang_str(LANG_LOG_CONFIG_HTTPSPROXYAUTHENTICATOR_TOO_LONG));
	}

	if(options->CorporateProxy)	/* parse it now */
	{	if(tor_addr_port_parse(options->CorporateProxy,&options->CorporateProxyAddr, &options->CorporateProxyPort) <0)
			REJECT(get_lang_str(LANG_LOG_CONFIG_NTLMPROXY_PARSE_FAILED));
		if(options->CorporateProxyPort == 0)	/* give it a default */
			options->CorporateProxyPort = 8080;
	}
	if(options->CorporateProxyAuthenticator)
	{	if(strlen(options->CorporateProxyAuthenticator) >= 512)
			REJECT(get_lang_str(LANG_LOG_CONFIG_NTLMPROXYAUTHENTICATOR_TOO_LONG));
	}

  if (options->HashedControlPassword) {
    smartlist_t *sl = decode_hashed_passwords(options->HashedControlPassword);
    if (!sl) {
      REJECT(get_lang_str(LANG_LOG_CONFIG_HASHEDCONTROLPASSWORD_BAD));
    } else {
      SMARTLIST_FOREACH(sl, char*, cp, tor_free(cp));
      smartlist_free(sl);
    }
  }

  if (options->HashedControlSessionPassword) {
    smartlist_t *sl = decode_hashed_passwords(
                                  options->HashedControlSessionPassword);
    if (!sl) {
      REJECT(get_lang_str(LANG_LOG_CONFIG_HASHEDCONTROLSESSIONPASSWORD_BAD));
    } else {
      SMARTLIST_FOREACH(sl, char*, cp, tor_free(cp));
      smartlist_free(sl);
    }
  }

  if (options->ControlListenAddress) {
    int all_are_local = 1;
    config_line_t *ln;
    for (ln = options->ControlListenAddress; ln; ln = ln->next) {
      if (strcmpstart((char *)ln->value, "127."))
        all_are_local = 0;
    }
    if (!all_are_local) {
      if (!options->HashedControlPassword &&
          !options->HashedControlSessionPassword &&
          !options->CookieAuthentication) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONTROL_NO_AUTH));
        options->ControlPort = 0;
      } else {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONTROL_NOT_LOCAL));
      }
    }
  }

  if (options->ControlPort && !options->HashedControlPassword &&
      !options->HashedControlSessionPassword &&
      !options->CookieAuthentication) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONTROLPORT_NO_AUTH));
  }

#ifndef int3
  if (options->UseEntryGuards && ! options->NumEntryGuards)
    REJECT(get_lang_str(LANG_LOG_CONFIG_USEENTRYGUARDS_WITHOUT_NUMENTRYGUARDS));

  if (check_nickname_list(options->MyFamily, "MyFamily", msg))
    return -1;
  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (check_nickname_list(cl->value, "NodeFamily", msg))
      return -1;
  }
#endif

  if (validate_addr_policies(options, msg) < 0)
    return -1;

  if (validate_dir_authorities(options, old_options) < 0)
    REJECT(get_lang_str(LANG_LOG_CONFIG_DIR_AUTH_LINE_PARSE_FAILED));

  if (options->UseBridges && !options->Bridges)	options->UseBridges=0;
//    REJECT(get_lang_str(LANG_LOG_CONFIG_USEBRIDGES_WITHOUT_BRIDGES));
//  if (options->UseBridges && !options->TunnelDirConns)
//    REJECT(get_lang_str(LANG_LOG_CONFIG_USEBRIDGES_WITHOUT_TUNNELDIRCONS));
  if (options->Bridges) {
    for (cl = options->Bridges; cl; cl = cl->next) {
      if (parse_bridge_line((char *)cl->value, 1)<0)
        REJECT(get_lang_str(LANG_LOG_CONFIG_BRIDGE_LINE_PARSE_FAILED));
    }
  }

  if (options->ConstrainedSockets) {
    /* If the user wants to constrain socket buffer use, make sure the desired
     * limit is between MIN|MAX_TCPSOCK_BUFFER in k increments. */
    if (options->ConstrainedSockSize > MAX_CONSTRAINED_TCP_BUFFER ||
        options->ConstrainedSockSize % 1024) {
      tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_CONSTRAINEDSOCKSIZE_INVALID),MIN_CONSTRAINED_TCP_BUFFER, MAX_CONSTRAINED_TCP_BUFFER);
      return -1;
    }
    if (options->DirPort) {
      /* Providing cached directory entries while system TCP buffers are scarce
       * will exacerbate the socket errors.  Suggest that this be disabled. */
      COMPLAIN(get_lang_str(LANG_LOG_CONFIG_CONSTRAINED_SOCKET_BUFFERS));
    }
  }

  if (options->V3AuthVoteDelay + options->V3AuthDistDelay >=
      options->V3AuthVotingInterval/2) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHVOTINGINTERVAL_TOO_LOW));
  }
  if (options->V3AuthVoteDelay < MIN_VOTE_SECONDS)
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHVOTEDELAY_TOO_LOW));
  if (options->V3AuthDistDelay < MIN_DIST_SECONDS)
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHDISTDELAY_TOO_LOW));

  if (options->V3AuthNIntervalsValid < 2)
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHNINTERVALSVALID_TOO_LOW));

  if (options->V3AuthVotingInterval < MIN_VOTE_INTERVAL) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHVOTINGINTERVAL_TOO_LOW_2));
  } else if (options->V3AuthVotingInterval > 24*60*60) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_V3AUTHVOTINGINTERVAL_TOO_HIGH));
  } else if (((24*60*60) % options->V3AuthVotingInterval) != 0) {
    COMPLAIN(get_lang_str(LANG_LOG_CONFIG_V3AUTHVOTINGINTERVAL_IS_NOT_DAYS));
  }

  if (rend_config_services(options, 1) < 0)
    REJECT(get_lang_str(LANG_LOG_CONFIG_RENDEZVOUS_CONFIG_FAILED));

  /* Parse client-side authorization for hidden services. */
  if (rend_parse_service_authorization(options, 1) < 0)
    REJECT(get_lang_str(LANG_LOG_CONFIG_RENDEZVOUS_AUTH_CONFIG_FAILED));

  if (parse_virtual_addr_network(options->VirtualAddrNetwork, 1, NULL)<0)
    return -1;

  if (options->AutomapHostsSuffixes) {
    SMARTLIST_FOREACH(options->AutomapHostsSuffixes, char *, suf,
    {
      size_t len = strlen(suf);
      if (len && suf[len-1] == '.')
        suf[len-1] = '\0';
    });
  }

  if (options->TestingTorNetwork && !options->DirServers) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGTORNETWORK_WITH_DEFAULT_DIRSERVERS));
  }

  /*XXXX022 checking for defaults manually like this is a bit fragile.*/

  /* Keep changes to hard-coded values synchronous to man page and default
   * values table. */
  if (options->TestingV3AuthInitialVotingInterval != 30*60 &&
      !options->TestingTorNetwork && !options->_UsingTestNetworkDefaults) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTINGINTERVAL_WITHOUT_TESTINGTORNETWORK));
  } else if (options->TestingV3AuthInitialVotingInterval < MIN_VOTE_INTERVAL) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTINGINTERVAL_TOO_LOW));
  } else if (((30*60) % options->TestingV3AuthInitialVotingInterval) != 0) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTINGINTERVAL_MUST_DIVIDE_TO_30_MIN));
  }

  if (options->TestingV3AuthInitialVoteDelay != 5*60 &&
      !options->TestingTorNetwork && !options->_UsingTestNetworkDefaults) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTEDLEAY_WITHOUT_TESTINGTORNETWORK));
  } else if (options->TestingV3AuthInitialVoteDelay < MIN_VOTE_SECONDS) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTEDELAY_TOO_LOW));
  }

  if (options->TestingV3AuthInitialDistDelay != 5*60 &&
      !options->TestingTorNetwork && !options->_UsingTestNetworkDefaults) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALDISTDELAY_WITHOUT_TESTINGTORNETWORK));
  } else if (options->TestingV3AuthInitialDistDelay < MIN_DIST_SECONDS) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALDISTDELAY_TOO_LOW));
  }

  if (options->TestingV3AuthInitialVoteDelay +
      options->TestingV3AuthInitialDistDelay >=
      options->TestingV3AuthInitialVotingInterval/2) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGV3AUTHINITIALVOTINGINTERVAL_TOO_LOW_2));
  }

  if (options->TestingAuthDirTimeToLearnReachability != 30*60 &&
      !options->TestingTorNetwork && !options->_UsingTestNetworkDefaults) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGAUTHDIRTIMETOLEARNREACHABILITY_WITHOUT_TESTINGTORNETWORK));
  } else if (options->TestingAuthDirTimeToLearnReachability < 0) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGAUTHDIRTIMETOLEARNREACHABILITY_NEGATIVE));
  } else if (options->TestingAuthDirTimeToLearnReachability > 2*60*60) {
    COMPLAIN(get_lang_str(LANG_LOG_CONFIG_TESTINGAUTHDIRTIMETOLEARNREACHABILITY_TOO_HIGH));
  }

  if (options->TestingEstimatedDescriptorPropagationTime != 10*60 &&
      !options->TestingTorNetwork && !options->_UsingTestNetworkDefaults) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGESTIMATEDDESCRIPTORPROPAGATIONTIME_WITHOUT_TESTINGTORNETWORK));
  } else if (options->TestingEstimatedDescriptorPropagationTime < 0) {
    REJECT(get_lang_str(LANG_LOG_CONFIG_TESTINGESTIMATEDDESCRIPTORPROPAGATIONTIME_NEGATIVE));
  } else if (options->TestingEstimatedDescriptorPropagationTime > 60*60) {
    COMPLAIN(get_lang_str(LANG_LOG_CONFIG_TESTINGESTIMATEDDESCRIPTORPROPAGATIONTIME_TOO_HIGH));
  }

  if (options->TestingTorNetwork) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_TESTINGTORNETWORK_IS_SET));
  }

  return 0;
#undef REJECT
#undef COMPLAIN
}

/** Helper: return true iff s1 and s2 are both NULL, or both non-NULL
 * equal strings. */
static int
opt_streq(const char *s1, const char *s2)
{
  if (!s1 && !s2)
    return 1;
  else if (s1 && s2 && !strcmp(s1,s2))
    return 1;
  else
    return 0;
}

/** Return 1 if any change from <b>old_options</b> to <b>new_options</b>
 * will require us to rotate the cpu and dns workers; else return 0. */
static int
options_transition_affects_workers(or_options_t *old_options,
                                   or_options_t *new_options)
{
  if (old_options->NumCpus != new_options->NumCpus ||
      old_options->ORPort != new_options->ORPort ||
      old_options->ServerDNSSearchDomains !=
                                       new_options->ServerDNSSearchDomains ||
      old_options->SafeLogging != new_options->SafeLogging ||
      old_options->ClientOnly != new_options->ClientOnly ||
      !config_lines_eq(old_options->Logs, new_options->Logs))
    return 1;

  /* Check whether log options match. */

  /* Nothing that changed matters. */
  return 0;
}

/** Return 1 if any change from <b>old_options</b> to <b>new_options</b>
 * will require us to generate a new descriptor; else return 0. */
static int
options_transition_affects_descriptor(or_options_t *old_options,
                                      or_options_t *new_options)
{
  /* XXX We can be smarter here. If your DirPort isn't being
   * published and you just turned it off, no need to republish. If
   * you changed your bandwidthrate but maxadvertisedbandwidth still
   * trumps, no need to republish. Etc. */
  if (!opt_streq(old_options->Nickname,new_options->Nickname) ||
      !opt_streq(old_options->Address,new_options->Address) ||
      !config_lines_eq(old_options->ExitPolicy,new_options->ExitPolicy) ||
      old_options->ExitPolicyRejectPrivate !=
        new_options->ExitPolicyRejectPrivate ||
      old_options->ORPort != new_options->ORPort ||
      old_options->DirPort != new_options->DirPort ||
      old_options->ClientOnly != new_options->ClientOnly ||
      old_options->NoPublish != new_options->NoPublish ||
      old_options->_PublishServerDescriptor !=
        new_options->_PublishServerDescriptor ||
      old_options->BandwidthRate != new_options->BandwidthRate ||
      old_options->BandwidthBurst != new_options->BandwidthBurst ||
      old_options->MaxAdvertisedBandwidth !=
        new_options->MaxAdvertisedBandwidth ||
      !opt_streq(old_options->ContactInfo, new_options->ContactInfo) ||
      !opt_streq(old_options->MyFamily, new_options->MyFamily) ||
      !opt_streq(old_options->AccountingStart, new_options->AccountingStart) ||
      old_options->AccountingMax != new_options->AccountingMax)
    return 1;

  return 0;
}


/** Verify whether lst is a string containing valid-looking comma-separated
 * nicknames, or NULL. Return 0 on success. Warn and return -1 on failure.
 */
#ifndef int3
static int
check_nickname_list(const char *lst, const char *name, char **msg)
{
  int r = 0;
  smartlist_t *sl;

  if (!lst)
    return 0;
  sl = smartlist_create();

  smartlist_split_string(sl, lst, ",",
    SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK|SPLIT_STRIP_SPACE, 0);

  SMARTLIST_FOREACH(sl, const char *, s,
    {
      if (!is_legal_nickname_or_hexdigest(s)) {
        tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_INVALID_NICKNAME_IN_LINE),s,name);
        r = -1;
        break;
      }
    });
  SMARTLIST_FOREACH(sl, char *, s, tor_free(s));
  smartlist_free(sl);
  return r;
}
#endif

/** Learn config file name from command line arguments, or use the default */
static char *find_torrc_filename(int argc, char **argv,int *using_default_torrc, int *ignore_missing_torrc)
{	char *fname=NULL;
	int i;

	for(i = 1; i < argc; ++i)
	{	if(i < argc-1 && !strcmp(argv[i],"-f"))
		{	if(fname)
			{	log(LOG_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DUPLICATE_F_OPTIONS));
				tor_free(fname);
			}
			fname = tor_strdup(argv[i+1]);
			*using_default_torrc = 0;
			++i;
		}
		else if(!strcmp(argv[i],"--ignore-missing-torrc"))
			*ignore_missing_torrc = 1;
	}

	if(*using_default_torrc)	/* didn't find one, try CONFDIR */
	{	const char *dflt = get_default_conf_file();
		fname = tor_strdup(dflt);
	}
	return fname;
}

/** Load torrc from disk, setting torrc_fname if successful */
static char *load_torrc_from_disk(int argc, char **argv)
{	char *fname=NULL;
	char *cf = NULL;
	int using_default_torrc = 1;
	int ignore_missing_torrc = 0;
	fname = find_torrc_filename(argc, argv,&using_default_torrc, &ignore_missing_torrc);
	tor_assert(fname);
	log(LOG_DEBUG, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_OPENING_CONFIG_FILE),fname);
	tor_free(torrc_fname);
	torrc_fname = fname;

	/* Open config file */
	if(file_status(fname) != FN_FILE || !(cf = read_file_to_str(fname,0,NULL)))
	{	if(using_default_torrc == 1 || ignore_missing_torrc)
		{	log(LOG_NOTICE, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONFIG_FILE_MISSING),fname);
			tor_free(fname); /* sets fname to NULL */
			torrc_fname = NULL;
			cf = tor_strdup("");
		}
		else
		{	log(LOG_WARN, LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONFIG_FILE_OPEN_ERROR),fname);
			tor_free(fname);
			torrc_fname = NULL;
			return NULL;
		}
	}
	return cf;
}

/** Read a configuration file into <b>options</b>, finding the configuration
 * file location based on the command line.  After loading the file
 * call options_init_from_string() to load the config.
 * Return 0 if success, -1 if failure. */
int options_init_from_torrc(int argc, char **argv)
{	char *cf=NULL;
	int i, retval, command;
	static char **backup_argv;
	static int backup_argc;
	char *command_arg = NULL;
	unsigned char *errmsg=NULL;

	if(argv)	/* first time we're called. save commandline args */
	{	backup_argv = argv;
		backup_argc = argc;
	}
	else		/* we're reloading. need to clean up old options first. */
	{	argv = backup_argv;
		argc = backup_argc;
	}

	if(argc > 1)
	{	if(!strcmp(argv[1], "--list-torrc-options"))	/* For documenting validating whether we've documented everything. */
		{	list_torrc_options();
			exit(0);
		}
		else if(!strcmp(argv[1],"--version"))
		{	printf("Advanced Onion Router version %s.\r\n",advtor_ver);
			exit(0);
		}
	}
	/* Go through command-line variables */
	if(global_cmdline_options || config_get_commandlines(argc, argv, &global_cmdline_options) >= 0)
	{	command = CMD_RUN_TOR;
		for(i = 1; i < argc; ++i)
		{	if(!strcmp(argv[i],"--list-fingerprint"))
				command = CMD_LIST_FINGERPRINT;
			else if(!strcmp(argv[i],"--hash-password"))
			{	command = CMD_HASH_PASSWORD;
				command_arg = tor_strdup( (i < argc-1) ? argv[i+1] : "");
				++i;
			}
			else if(!strcmp(argv[i],"--verify-config"))
				command = CMD_VERIFY_CONFIG;
			else if(!strcmp(argv[i],"--read-only"))
			{	load_all_files();
				set_read_only();
			}
			else if(!strcmp(argv[i],"--no-seh"))
			{	restore_seh();
			}
		}
		if (command == CMD_HASH_PASSWORD)	cf = tor_strdup("");
		else					cf = load_torrc_from_disk(argc, argv);
		if(cf)
		{	retval = options_init_from_string(cf, command, command_arg, &errmsg);
			tor_free(cf);
			if (retval >= 0)	return 0;
		}
	}
	if(errmsg)
	{	log(LOG_WARN,LD_CONFIG,"%s", errmsg);
		tor_free(errmsg);
	}
	return -1;
}

/** Load the options from the configuration in <b>cf</b>, validate
 * them for consistency and take actions based on them.
 *
 * Return 0 if success, negative on error:
 *  * -1 for general errors.
 *  * -2 for failure to parse/validate,
 *  * -3 for transition not allowed
 *  * -4 for error while setting the new options
 */
setopt_err_t options_init_from_string(const char *cf,int command, const char *command_arg,unsigned char **msg)
{	or_options_t *oldoptions, *newoptions;
	or_state_t *new_state = NULL;
	config_line_t *cl;
	char *msgerr = NULL;
	int retval;
	int badstate = 0;
	setopt_err_t err = SETOPT_ERR_MISC;
	tor_assert(msg);
	oldoptions = global_options;	/* get_options unfortunately asserts if this is the first time we run*/
	newoptions = tor_malloc_zero(sizeof(or_options_t));
	newoptions->_magic = OR_OPTIONS_MAGIC;
	new_state = tor_malloc_zero(sizeof(or_state_t));
	new_state->_magic = OR_STATE_MAGIC;
	options_init(newoptions);
	config_init(&state_format, new_state);
	newoptions->command = command;
	newoptions->command_arg = command_arg;
	/* get config lines, assign them */
	retval = config_get_lines(cf, &cl);
	if(retval >= 0)
	{	retval = config_assign(&state_format, new_state, cl, 0, 0, msg,"[state]");
		if(retval<0)	badstate = 1;
		if(*msg)
		{	log_warn(LD_GENERAL,"%s",*msg);
			tor_free(*msg);//*msg=NULL;
		}
		retval = config_assign(&options_format, newoptions, cl, 0, 0, msg,"[torrc]");
		config_free_lines(cl);
		if(retval >= 0)
		{	if(!badstate && or_state_validate(NULL, new_state, &msgerr) < 0)	badstate = 1;
			if(msgerr)
			{	log_warn(LD_GENERAL, "%s", msgerr);
				tor_free(msgerr);msgerr=NULL;
			}
			/* Go through command-line variables too */
			retval = config_assign(&options_format, newoptions,global_cmdline_options, 0, 0, msg,NULL);
		}
		/* If this is a testing network configuration, change defaults for a list of dependent config options, re-initialize newoptions with the new defaults, and assign all options to it second time. */
		if(retval >= 0 && newoptions->TestingTorNetwork)	/* XXXX this is a bit of a kludge.  perhaps there's a better way to do this?  We could, for example, make the parsing algorithm do two passes over the configuration.  If it finds any "suite" options like TestingTorNetwork, it could change the defaults before its second pass. Not urgent so long as this seems to work, but at any sign of trouble, let's clean it up.  -NM */
		{	/* Change defaults. */
			int i;
			for(i = 0;testing_tor_network_defaults[i].name;++i)
			{	config_var_t *new_var = &testing_tor_network_defaults[i];
				config_var_t *old_var = config_find_option(&options_format, new_var->name);
				tor_assert(new_var);
				tor_assert(old_var);
				old_var->initvalue = new_var->initvalue;
			}
			/* Clear newoptions and re-initialize them with new defaults. */
			config_free(&options_format, newoptions);
			newoptions = tor_malloc_zero(sizeof(or_options_t));
			newoptions->_magic = OR_OPTIONS_MAGIC;
			options_init(newoptions);
			newoptions->command = command;
			newoptions->command_arg = command_arg;
			/* Assign all options a second time. */
			retval = config_get_lines(cf, &cl);
			if(retval >= 0)
			{	retval = config_assign(&options_format, newoptions, cl, 0, 0, msg,"[torrc]");
				config_free_lines(cl);
				if(retval >= 0)	retval = config_assign(&options_format, newoptions,global_cmdline_options, 0, 0, msg,NULL);
			}
		}
		if(retval < 0)	err = SETOPT_ERR_PARSE;
		else if(options_validate(oldoptions, newoptions, msg) < 0)	/* Validate newoptions */
			err = SETOPT_ERR_PARSE; /*XXX make this a separate return value.*/
		else if(set_options(newoptions, msg))
			err = SETOPT_ERR_SETTING;
		else
		{	if(!badstate)
			{	if (global_state)
					config_free(&state_format, global_state);
				global_state = new_state;
				if (entry_guards_parse_state(global_state, 1, &msgerr)<0)
				{	log_warn(LD_GENERAL,"%s",msgerr);
					tor_free(msgerr);
				}
				if (rep_hist_load_state(global_state, &msgerr)<0)
				{	log_warn(LD_GENERAL,get_lang_str(LANG_LOG_CONFIG_UNPARSEABLE_BW_HISTORY),msgerr);
					tor_free(msgerr);
				}
				new_state = NULL;
				rep_hist_load_mtbf_data(get_time(NULL));
			}
			else if(new_state)	config_free(&state_format, new_state);
			return SETOPT_OK;
		}
	}
//	config_free(&options_format, newoptions);
	if(*msg)
	{	char *old_msg = (char *)*msg;
		tor_asprintf(msg,get_lang_str(LANG_LOG_CONFIG_CONFIG_PARSE_FAILED),*msg);
		tor_free(old_msg);
	}
	if(new_state)	config_free(&state_format, new_state);
	return err;
}

/** Return the location for our configuration file.
 */
const char *
get_torrc_fname(void)
{
  if (torrc_fname)
    return torrc_fname;
  else
    return get_default_conf_file();
}

/** Adjust the address map mased on the MapAddress elements in the
 * configuration <b>options</b>
 */
void
config_register_addressmaps(or_options_t *options)
{
  smartlist_t *elts;
  config_line_t *opt;
  char *from, *to;

  addressmap_clear_configured();
  elts = smartlist_create();
  for (opt = options->AddressMap; opt; opt = opt->next) {
    smartlist_split_string(elts, (char *)opt->value, NULL,
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 2);
    if (smartlist_len(elts) >= 2) {
      from = smartlist_get(elts,0);
      to = smartlist_get(elts,1);
      if (address_is_invalid_destination(to, 1)) {
        log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_INVALID_MAPADDRESS_ARGUMENT),to);
      } else {
        addressmap_register(from, tor_strdup(to), 0, ADDRMAPSRC_TORRC);
        if (smartlist_len(elts)>2) {
          log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_EXTRA_MAPADDRESS_ARGUMENTS));
        }
      }
    } else {
      log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_TOO_FEW_MAPADDRESS_ARGUMENTS),opt->value);
    }
    SMARTLIST_FOREACH(elts, char*, cp, tor_free(cp));
    smartlist_clear(elts);
  }
  smartlist_free(elts);
}


/** Read the contents of a Bridge line from <b>line</b>. Return 0
 * if the line is well-formed, and -1 if it isn't. If
 * <b>validate_only</b> is 0, and the line is well-formed, then add
 * the bridge described in the line to our internal bridge list. */
int parse_bridge_line(const char *line, int validate_only)
{	smartlist_t *items = NULL;
	int r = -1;
	char *addrport=NULL, *fingerprint=NULL;
	tor_addr_t addr;
	uint16_t port = 0;
	char digest[DIGEST_LEN];

	items = smartlist_create();
	smartlist_split_string(items, line, NULL,SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
	if(smartlist_len(items) < 1)
		log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_TOO_FEW_BRIDGE_ARGUMENTS));
	else
	{	addrport = smartlist_get(items, 0);
		smartlist_del_keeporder(items, 0);
		if(tor_addr_port_parse(addrport, &addr, &port)<0)
			log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_INVALID_BRIDGE_ADDRESS),addrport);
		else if(!port)
			log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_MISSING_PORT_IN_BRIDGE_ADDRESS),addrport);
		else
		{	if(smartlist_len(items))
			{	fingerprint = smartlist_join_strings(items, "", 0, NULL);
				if(strlen(fingerprint) != HEX_DIGEST_LEN)
					log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_INVALID_BRIDGE_KEY));
				else if(base16_decode(digest, DIGEST_LEN, fingerprint, HEX_DIGEST_LEN)<0)
					log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_ERROR_DECODING_BRIDGE_KEY));
				else r = 0;
			}
			else r = 0;
			if(!validate_only)
			{	log_debug(LD_DIR,get_lang_str(LANG_LOG_CONFIG_BRIDGE_AT), fmt_addr(&addr),(int)port,fingerprint ? fingerprint : get_lang_str(LANG_LOG_CONFIG_NO_BRIDGE_KEY));
				bridge_add_from_config(&addr, port, fingerprint ? digest : NULL);
			}
		}
	}
	SMARTLIST_FOREACH(items, char*, s, tor_free(s));
	smartlist_free(items);
	tor_free(addrport);
	tor_free(fingerprint);
	return r;
}

/** Read the contents of a DirServer line from <b>line</b>. If
 * <b>validate_only</b> is 0, and the line is well-formed, and it
 * shares any bits with <b>required_type</b> or <b>required_type</b>
 * is 0, then add the dirserver described in the line (minus whatever
 * bits it's missing) as a valid authority. Return 0 on success,
 * or -1 if the line isn't well-formed or if we can't add it. */
int parse_dir_server_line(const char *line, authority_type_t required_type,int validate_only)
{	smartlist_t *items = NULL;
	int r = -1;
	char *addrport=NULL, *address=NULL, *nickname=NULL, *fingerprint=NULL;
	uint16_t dir_port = 0,or_port = 0;
	char digest[DIGEST_LEN];
	char v3_digest[DIGEST_LEN];
	authority_type_t type = V2_AUTHORITY;
	int is_not_hidserv_authority = 0, is_not_v2_authority = 0;
	if((line!=NULL)&&(line[0]==';')) return 0;
	items = smartlist_create();
	smartlist_split_string(items, line, NULL,SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
	if(smartlist_len(items) < 1)
		log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_NO_ARGUMENTS));
	else
	{	if(is_legal_nickname(smartlist_get(items, 0)))
		{	nickname = smartlist_get(items, 0);
			smartlist_del_keeporder(items, 0);
		}
		while(smartlist_len(items))
		{	char *flag = smartlist_get(items, 0);
			if(TOR_ISDIGIT(flag[0]))	break;
			if(!strcasecmp(flag, "v1"))		type |= (V1_AUTHORITY | HIDSERV_AUTHORITY);
			else if(!strcasecmp(flag, "hs"))	type |= HIDSERV_AUTHORITY;
			else if(!strcasecmp(flag, "no-hs"))	is_not_hidserv_authority = 1;
			else if(!strcasecmp(flag, "bridge"))	type |= BRIDGE_AUTHORITY;
			else if(!strcasecmp(flag, "no-v2"))	is_not_v2_authority = 1;
			else if(!strcasecmpstart(flag, "orport="))
			{	int ok;
				char *portstring = flag + strlen("orport=");
				or_port = (uint16_t) tor_parse_long(portstring, 10, 1, 65535, &ok, NULL);
				if(!ok)	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_INVALID_ORPORT),portstring);
			}
			else if(!strcasecmpstart(flag, "v3ident="))
			{	char *idstr = flag + strlen("v3ident=");
				if(strlen(idstr) != HEX_DIGEST_LEN || base16_decode(v3_digest, DIGEST_LEN, idstr, HEX_DIGEST_LEN)<0)
					log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_BAD_V3_DIGEST),flag);
				else	type |= V3_AUTHORITY;
			}
			else	log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_UNRECOGNIZED_FLAG),flag);
			tor_free(flag);
			smartlist_del_keeporder(items, 0);
		}
		if(is_not_hidserv_authority)	type &= ~HIDSERV_AUTHORITY;
		if(is_not_v2_authority)		type &= ~V2_AUTHORITY;
		if(smartlist_len(items) < 2)
			log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_TOO_FEW_ARGUMENTS));
		else
		{	addrport = smartlist_get(items, 0);
			smartlist_del_keeporder(items, 0);
			if(parse_addr_port(LOG_WARN, addrport, &address, NULL, &dir_port)<0)
				log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_ADDR_ERROR),addrport);
			else
			{	if(!dir_port)
					log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_MISSING_PORT),addrport);
				else
				{	fingerprint = smartlist_join_strings(items, "", 0, NULL);
					if(strlen(fingerprint) != HEX_DIGEST_LEN)
						log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_KEY_ERROR),(int)strlen(fingerprint));
					else if(base16_decode(digest, DIGEST_LEN, fingerprint, HEX_DIGEST_LEN)<0)
						log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_KEY_DECODE_ERROR));
					else
					{	r = 0;
						if(!validate_only && (!required_type || required_type & type))
						{	if(required_type)	type &= required_type; /* pare down what we think of them as an authority for. */
							log_debug(LD_DIR,get_lang_str(LANG_LOG_CONFIG_DIRSERVER_TRUSTED),(int)type,address,(int)dir_port,(char*)smartlist_get(items,0));
							if(!add_trusted_dir_server(nickname, address, dir_port, or_port,digest, v3_digest, type))	r = -1;
						}
					}
				}
			}
		}
	}
	SMARTLIST_FOREACH(items, char*, s, tor_free(s));
	smartlist_free(items);
	tor_free(addrport);
	tor_free(address);
	tor_free(nickname);
	tor_free(fingerprint);
	return r;
}

/** This string must remain the same forevermore. It is how we
 * recognize that the torrc file doesn't need to be backed up. */
#define GENERATED_FILE_PREFIX "; This file was generated by Advanced Onion Router; " \
  "if you edit it, comments will not be preserved"

/** If writing the state to disk fails, try again after this many seconds. */
#define STATE_WRITE_RETRY_INTERVAL 3600

/** Save a configuration file for the configuration in <b>options</b>
 * into the file <b>fname</b>.  If the file already exists, and
 * doesn't begin with GENERATED_FILE_PREFIX, rename it.  Otherwise
 * replace it.  Return 0 on success, -1 on failure. */
static int write_configuration_file(char *fname, or_options_t *options)
{	unsigned char *old_val=NULL, *new_val=NULL, *new_conf=NULL;
	int rename_old = 0, r = -1;
	char *state=NULL;
	tor_assert(fname);

	switch(file_status(fname))
	{	case FN_FILE:
			old_val = (unsigned char *)read_file_to_str(fname, 0, NULL);
			if(strcmpstart((char *)old_val, GENERATED_FILE_PREFIX))
				rename_old = 1;
			tor_free(old_val);
			break;
		case FN_NOENT:
			break;
		case FN_ERROR:
		case FN_DIR:
		default:
			log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_CONFIG_FILE_NOT_A_FILE),fname);
			return -1;
	}
	if(!(new_conf = (unsigned char *)options_dump(options, 1)))
		log_warn(LD_BUG,get_lang_str(LANG_LOG_CONFIG_CONFIG_STRING_ERROR));
	else
	{	if(global_state==NULL)
		{	global_state = tor_malloc_zero(sizeof(or_state_t));
			global_state->_magic = OR_STATE_MAGIC;
			config_init(&state_format, global_state);
		}
		tor_assert(global_state);
		entry_guards_update_state(global_state);
		rep_hist_update_state(global_state);
		circuit_build_times_update_state(&circ_times, global_state);	///
		if(accounting_is_enabled(get_options()))	accounting_run_housekeeping(get_time(NULL));
		global_state->LastWritten = get_time(NULL);
		tor_free(global_state->TorVersion);
		tor_asprintf(&global_state->TorVersion, "Tor %s", get_version());
		state = config_dump(&state_format, global_state, 1, 0);
		if(state==NULL) state=tor_strdup("");
		tor_asprintf(&new_val,"%s\r\n\r\n%s\r\n\r\n%s\r\n\r\n[state]\r\n\r\n%s",GENERATED_FILE_PREFIX,"[torrc]",new_conf,state);
		r = 0;
		if(rename_old)
			r = make_backup(fname);
		if(r >= 0 && write_buf_to_file(fname,(char *)new_val,strlen((char *)new_val)) < 0)
		{	r = -1;
			global_state->next_write = get_time(NULL) + STATE_WRITE_RETRY_INTERVAL;
		}
		tor_free(new_val);
	}
	tor_free(new_conf);
	return r;
}

/**
 * Save the current configuration file value to disk.  Return 0 on
 * success, -1 on failure.
 **/
int
options_save_current(void)
{
  iplist_write();
  if (torrc_fname) {
    /* This fails if we can't write to our configuration file.
     *
     * If we try falling back to datadirectory or something, we have a better
     * chance of saving the configuration, but a better chance of doing
     * something the user never expected. Let's just warn instead. */
    if(global_options)
      global_options->Logging=global_options->logging;
    return write_configuration_file(torrc_fname, get_options());
  }
  return write_configuration_file(get_default_conf_file(), get_options());
}

/** Mapping from a unit name to a multiplier for converting that unit into a
 * base unit. */
struct unit_table_t {
  const char *unit;
  uint64_t multiplier;
};

/** Table to map the names of memory units to the number of bytes they
 * contain. */
static struct unit_table_t memory_units[] = {
  { "",          1 },
  { "b",         1<< 0 },
  { "byte",      1<< 0 },
  { "bytes",     1<< 0 },
  { "kb",        1<<10 },
  { "kbyte",     1<<10 },
  { "kbytes",    1<<10 },
  { "kilobyte",  1<<10 },
  { "kilobytes", 1<<10 },
  { "m",         1<<20 },
  { "mb",        1<<20 },
  { "mbyte",     1<<20 },
  { "mbytes",    1<<20 },
  { "megabyte",  1<<20 },
  { "megabytes", 1<<20 },
  { "gb",        1<<30 },
  { "gbyte",     1<<30 },
  { "gbytes",    1<<30 },
  { "gigabyte",  1<<30 },
  { "gigabytes", 1<<30 },
  { "tb",        U64_LITERAL(1)<<40 },
  { "terabyte",  U64_LITERAL(1)<<40 },
  { "terabytes", U64_LITERAL(1)<<40 },
  { NULL, 0 },
};

/** Table to map the names of time units to the number of seconds they
 * contain. */
static struct unit_table_t time_units[] = {
  { "",         1 },
  { "second",   1 },
  { "seconds",  1 },
  { "minute",   60 },
  { "minutes",  60 },
  { "hour",     60*60 },
  { "hours",    60*60 },
  { "day",      24*60*60 },
  { "days",     24*60*60 },
  { "week",     7*24*60*60 },
  { "weeks",    7*24*60*60 },
  { NULL, 0 },
};

/** Parse a string <b>val</b> containing a number, zero or more
 * spaces, and an optional unit string.  If the unit appears in the
 * table <b>u</b>, then multiply the number by the unit multiplier.
 * On success, set *<b>ok</b> to 1 and return this product.
 * Otherwise, set *<b>ok</b> to 0.
 */
static uint64_t
config_parse_units(const char *val, struct unit_table_t *u, int *ok)
{
  uint64_t v = 0;
  double d = 0;
  int use_float = 0;
  char *cp;

  tor_assert(ok);

  v = tor_parse_uint64(val, 10, 0, UINT64_MAX, ok, &cp);
  if (!*ok || (cp && *cp == '.')) {
    d = tor_parse_double(val, 0, (double)UINT64_MAX, ok, &cp);
    if (!*ok)
      return 0;
    use_float = 1;
  }

  if ((!cp)||(!*cp)) {
    *ok = 1;
    v = use_float ? DBL_TO_U64(d) :  v;
    return v;
  }
  cp = (char*) eat_whitespace(cp);

  for ( ;u->unit;++u) {
    if (!strcasecmp(u->unit, cp)) {
      if (use_float)
        v = u->multiplier * tor_lround(d);
      else
        v *= u->multiplier;
      *ok = 1;
      return v;
    }
  }
  log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_UNKNOWN_UNIT),cp);
  *ok = 1;
  return 0;
}

/** Parse a string in the format "number unit", where unit is a unit of
 * information (byte, KB, M, etc).  On success, set *<b>ok</b> to true
 * and return the number of bytes specified.  Otherwise, set
 * *<b>ok</b> to false and return 0. */
static uint64_t
config_parse_memunit(const char *s, int *ok)
{
  uint64_t u = config_parse_units(s, memory_units, ok);
  return u;
}

/** Parse a string in the format "number unit", where unit is a unit of time.
 * On success, set *<b>ok</b> to true and return the number of seconds in
 * the provided interval.  Otherwise, set *<b>ok</b> to 0 and return -1.
 */
static int
config_parse_interval(const char *s, int *ok)
{
  uint64_t r;
  r = config_parse_units(s, time_units, ok);
  if (!ok)
    return -1;
  if (r > INT_MAX) {
    log_warn(LD_CONFIG,get_lang_str(LANG_LOG_CONFIG_INTERVAL_TOO_LONG),s);
    *ok = 0;
    return -1;
  }
  return (int)r;
}


/**
 * Initialize the libevent library.
 */
static void
init_libevent(void)
{
  const char *badness=NULL;

  configure_libevent_logging();
  /* If the kernel complains that some method (say, epoll) doesn't
   * exist, we don't care about it, since libevent will cope.
   */
  suppress_libevent_log_msg("Function not implemented");

  tor_check_libevent_header_compatibility();

  tor_libevent_initialize();

  suppress_libevent_log_msg(NULL);

  tor_check_libevent_version(tor_libevent_get_method(),
                             get_options()->ORPort != 0,
                             &badness);
  if (badness) {
    const char *v = tor_libevent_get_version_str();
    const char *m = tor_libevent_get_method();
    control_event_general_status(LOG_WARN,
        "BAD_LIBEVENT VERSION=%s METHOD=%s BADNESS=%s RECOVERED=NO",
                                 v, m, badness);
  }
}

/** Return the persistent state struct for this Tor. */
or_state_t *
get_or_state(void)
{
  tor_assert(global_state);
  return global_state;
}

/** Return 0 if every setting in <b>state</b> is reasonable, and a
 * permissible transition from <b>old_state</b>.  Else warn and return -1.
 * Should have no side effects, except for normalizing the contents of
 * <b>state</b>.
 */
/* XXX from_setconf is here because of bug 238 */
static int
or_state_validate(or_state_t *old_state, or_state_t *state,char **msg)
{
  /* We don't use these; only options do. Still, we need to match that
   * signature. */
  (void) old_state;

  if (entry_guards_parse_state(state, 0, msg)<0)
    return -1;

  return 0;
}

/** Helper to implement GETINFO functions about configuration variables (not
 * their values).  Given a "config/names" question, set *<b>answer</b> to a
 * new string describing the supported configuration variables and their
 * types. */
int
getinfo_helper_config(control_connection_t *conn,
                      const char *question, char **answer,
                      const char **errmsg)
{
  (void) conn;
  (void) errmsg;
  if (!strcmp(question, "config/names")) {
    smartlist_t *sl = smartlist_create();
    int i;
    for (i = 0; _option_vars[i].name; ++i) {
      config_var_t *var = &_option_vars[i];
      const char *type, *desc;
      char *line;
      size_t len;
      desc = config_find_description(&options_format, var->name);
      switch (var->type) {
        case CONFIG_TYPE_STRING: type = "String"; break;
        case CONFIG_TYPE_FILENAME: type = "Filename"; break;
        case CONFIG_TYPE_UINT: type = "Integer"; break;
        case CONFIG_TYPE_INTERVAL: type = "TimeInterval"; break;
        case CONFIG_TYPE_MEMUNIT: type = "DataSize"; break;
        case CONFIG_TYPE_DOUBLE: type = "Float"; break;
        case CONFIG_TYPE_BOOL: type = "Boolean"; break;
        case CONFIG_TYPE_ISOTIME: type = "Time"; break;
        case CONFIG_TYPE_ROUTERSET: type = "RouterList"; break;
        case CONFIG_TYPE_CSV: type = "CommaList"; break;
        case CONFIG_TYPE_LINELIST: type = "LineList"; break;
        case CONFIG_TYPE_LINELIST_S: type = "Dependant"; break;
        case CONFIG_TYPE_LINELIST_V: type = "Virtual"; break;
	case CONFIG_TYPE_PORT: type = "Port"; break;
        default:
        case CONFIG_TYPE_OBSOLETE:
          type = NULL; break;
      }
      if (!type)
        continue;
      len = strlen(var->name)+strlen(type)+16;
      if (desc)
        len += strlen(desc);
      line = tor_malloc(len);
      if (desc)
        tor_snprintf(line, len, "%s %s %s\n",var->name,type,desc);
      else
        tor_snprintf(line, len, "%s %s\n",var->name,type);
      smartlist_add(sl, line);
    }
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
  return 0;
}
