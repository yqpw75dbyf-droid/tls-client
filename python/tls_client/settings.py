"""The client identifiers the Go core accepts, mirrored from
profiles.MappedTLSClients in ../../profiles/profiles.go.

Keep this list in sync when profiles are added on the Go side. It exists so
that a typo in a preset name fails fast in Python with a clear message,
instead of silently falling back to the default profile inside Go.
"""

CLIENT_IDENTIFIERS = frozenset(
    {
        # Chrome
        "chrome_103", "chrome_104", "chrome_105", "chrome_106", "chrome_107",
        "chrome_108", "chrome_109", "chrome_110", "chrome_111", "chrome_112",
        "chrome_117", "chrome_120", "chrome_124", "chrome_131", "chrome_133",
        "chrome_144", "chrome_146", "chrome_150", "chrome_152", "chrome_153",
        # Edge
        "edge_153",
        # Brave
        "brave_146",
        # Safari desktop (macOS)
        "safari_15_3", "safari_15_5", "safari_15_6_1", "safari_16_0",
        "safari_16_1", "safari_16_2", "safari_16_3", "safari_16_4",
        "safari_16_5", "safari_16_6", "safari_17_0", "safari_17_1",
        "safari_17_2", "safari_17_3", "safari_17_4", "safari_17_5",
        "safari_17_6", "safari_18_0", "safari_18_1", "safari_18_2",
        "safari_18_3", "safari_18_4", "safari_18_5", "safari_18_6",
        "safari_26_0", "safari_26_1", "safari_26_2", "safari_26_3",
        "safari_26_4", "safari_26_5", "safari_26_6",
        # Safari iOS / iPad
        "safari_ipad_15_6", "safari_ios_15_5", "safari_ios_15_6",
        "safari_ios_16_0", "safari_ios_17_0", "safari_ios_18_0",
        "safari_ios_18_5", "safari_ios_26_0",
        # Firefox
        "firefox_102", "firefox_104", "firefox_105", "firefox_106",
        "firefox_108", "firefox_110", "firefox_117", "firefox_120",
        "firefox_123", "firefox_132", "firefox_133", "firefox_135",
        "firefox_147", "firefox_148",
        # Tor Browser
        "tor_14_0", "tor_14_5", "tor_15_0",
        # Opera
        "opera_89", "opera_90", "opera_91", "opera_92", "opera_93",
        "opera_94", "opera_95", "opera_96", "opera_97", "opera_98",
        "opera_99", "opera_100", "opera_101", "opera_102", "opera_103",
        "opera_104", "opera_105", "opera_106", "opera_107", "opera_108",
        "opera_109", "opera_110", "opera_111", "opera_112", "opera_113",
        "opera_114", "opera_115", "opera_116", "opera_117", "opera_118",
        "opera_119", "opera_120", "opera_121", "opera_122", "opera_123",
        "opera_124", "opera_125", "opera_126", "opera_127", "opera_128",
        "opera_129", "opera_130", "opera_131", "opera_132", "opera_133",
        "opera_134", "opera_135", "opera_136",
        # App profiles
        "zalando_android_mobile", "zalando_ios_mobile", "nike_ios_mobile",
        "nike_android_mobile", "cloudscraper", "mms_ios", "mms_ios_1",
        "mms_ios_2", "mms_ios_3", "mesh_ios", "mesh_ios_1", "mesh_ios_2",
        "mesh_android", "mesh_android_1", "mesh_android_2", "confirmed_ios",
        "confirmed_android", "okhttp4_android_7", "okhttp4_android_8",
        "okhttp4_android_9", "okhttp4_android_10", "okhttp4_android_11",
        "okhttp4_android_12", "okhttp4_android_13",
    }
)
