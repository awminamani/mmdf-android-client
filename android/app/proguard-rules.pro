# Keep our JNI entry points so R8 doesn't strip them in release builds.
-keep class com.awminamani.mmdf.Native { *; }
-keep class com.awminamani.mmdf.MmdfVpnService { *; }
