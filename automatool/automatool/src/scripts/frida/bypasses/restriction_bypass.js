/**
 * RestrictionBypass Enhanced API Access Script
 * 
 * This script leverages RestrictionBypass library to access hidden Android APIs
 * that are normally restricted by Google's non-SDK interface restrictions.
 * 
 * Features:
 * - Automatic RestrictionBypass detection and initialization
 * - Enhanced permission analysis using hidden APIs
 * - System service access bypassing normal restrictions
 * - Hidden API method invocation logging
 * 
 * Usage: Load this script when RestrictionBypass library is present in target app
 */

console.log("[RestrictionBypass] Starting enhanced API access script...");

Java.perform(function() {
    
    // Check if RestrictionBypass is available in the target application
    var restrictionBypassAvailable = false;
    
    try {
        var BypassProvider = Java.use("com.github.ChickenHook.RestrictionBypass.BypassProvider");
        restrictionBypassAvailable = true;
        console.log("[RestrictionBypass] ✅ RestrictionBypass library detected - Enhanced access enabled");
    } catch (e) {
        console.log("[RestrictionBypass] ⚠️  RestrictionBypass library not found - Using standard hooks only");
        console.log("[RestrictionBypass] 💡 To enable enhanced features, integrate RestrictionBypass library in target app");
    }
    
    // Enhanced Permission Manager Access
    if (restrictionBypassAvailable) {
        try {
            console.log("[RestrictionBypass] 🔓 Attempting to access hidden Permission Manager APIs...");
            
            // Access normally restricted PermissionManager class
            var PermissionManager = Java.use("android.permission.PermissionManager");
            
            // Hook getPermissionFlags - normally restricted
            PermissionManager.getPermissionFlags.overload('java.lang.String', 'java.lang.String', 'int').implementation = function(permissionName, packageName, userId) {
                var result = this.getPermissionFlags(permissionName, packageName, userId);
                
                console.log("[RestrictionBypass] 🔍 Enhanced Permission Check:");
                console.log("  Package: " + packageName);
                console.log("  Permission: " + permissionName);
                console.log("  Flags: " + result + " (0x" + result.toString(16) + ")");
                console.log("  User ID: " + userId);
                
                // Decode permission flags
                var flagDescriptions = [];
                if (result & 0x1) flagDescriptions.push("GRANTED");
                if (result & 0x2) flagDescriptions.push("POLICY_FIXED");
                if (result & 0x4) flagDescriptions.push("SYSTEM_FIXED");
                if (result & 0x8) flagDescriptions.push("USER_SET");
                if (result & 0x10) flagDescriptions.push("USER_FIXED");
                if (result & 0x20) flagDescriptions.push("REVIEW_REQUIRED");
                
                if (flagDescriptions.length > 0) {
                    console.log("  Flag Details: " + flagDescriptions.join(" | "));
                }
                
                return result;
            };
            
            console.log("[RestrictionBypass] ✅ Permission Manager hooks installed");
            
        } catch (e) {
            console.log("[RestrictionBypass] ❌ Failed to hook Permission Manager: " + e.message);
        }
    }
    
    // Enhanced Package Manager Access
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        
        // Hook getApplicationInfo with enhanced logging
        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            var result = this.getApplicationInfo(packageName, flags);
            
            if (restrictionBypassAvailable) {
                console.log("[RestrictionBypass] 📱 Enhanced App Info Request:");
                console.log("  Package: " + packageName);
                console.log("  Flags: " + flags + " (0x" + flags.toString(16) + ")");
                console.log("  Target SDK: " + result.targetSdkVersion.value);
                console.log("  Min SDK: " + result.minSdkVersion.value);
                console.log("  App Flags: " + result.flags.value + " (0x" + result.flags.value.toString(16) + ")");
                
                // Check for system app flags
                var appFlags = result.flags.value;
                var systemFlags = [];
                if (appFlags & 0x1) systemFlags.push("SYSTEM");
                if (appFlags & 0x80) systemFlags.push("UPDATED_SYSTEM_APP");
                if (appFlags & 0x2) systemFlags.push("DEBUGGABLE");
                if (appFlags & 0x8000000) systemFlags.push("PRIVILEGED");
                
                if (systemFlags.length > 0) {
                    console.log("  System Flags: " + systemFlags.join(" | "));
                }
            }
            
            return result;
        };
        
        console.log("[RestrictionBypass] ✅ Package Manager hooks installed");
        
    } catch (e) {
        console.log("[RestrictionBypass] ❌ Failed to hook Package Manager: " + e.message);
    }
    
    // Enhanced System Service Access
    if (restrictionBypassAvailable) {
        try {
            var Context = Java.use("android.content.Context");
            
            // Hook getSystemService to log hidden service access
            Context.getSystemService.overload('java.lang.String').implementation = function(serviceName) {
                var result = this.getSystemService(serviceName);
                
                // Log access to sensitive system services
                var sensitiveServices = [
                    "permission",
                    "device_policy",
                    "user",
                    "account",
                    "activity",
                    "package",
                    "telephony"
                ];
                
                if (sensitiveServices.includes(serviceName)) {
                    console.log("[RestrictionBypass] 🔧 System Service Access:");
                    console.log("  Service: " + serviceName);
                    console.log("  Result: " + (result ? result.$className : "null"));
                }
                
                return result;
            };
            
            console.log("[RestrictionBypass] ✅ System Service hooks installed");
            
        } catch (e) {
            console.log("[RestrictionBypass] ❌ Failed to hook System Services: " + e.message);
        }
    }
    
    // Hidden API Method Invocation Logger
    if (restrictionBypassAvailable) {
        try {
            // Hook Class.forName to detect hidden API access attempts
            var Class = Java.use("java.lang.Class");
            
            Class.forName.overload('java.lang.String').implementation = function(className) {
                var result = this.forName(className);
                
                // Log access to potentially restricted classes
                var restrictedPatterns = [
                    "android.permission.",
                    "android.app.ActivityManagerNative",
                    "android.os.ServiceManager",
                    "com.android.internal.",
                    "android.telephony.TelephonyManager"
                ];
                
                for (var i = 0; i < restrictedPatterns.length; i++) {
                    if (className.includes(restrictedPatterns[i])) {
                        console.log("[RestrictionBypass] 🎯 Hidden API Class Access:");
                        console.log("  Class: " + className);
                        console.log("  Pattern: " + restrictedPatterns[i]);
                        break;
                    }
                }
                
                return result;
            };
            
            console.log("[RestrictionBypass] ✅ Hidden API detection hooks installed");
            
        } catch (e) {
            console.log("[RestrictionBypass] ❌ Failed to install hidden API hooks: " + e.message);
        }
    }
    
    // Enhanced Reflection Monitoring
    try {
        var Method = Java.use("java.lang.reflect.Method");
        
        Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function(obj, args) {
            var result = this.invoke(obj, args);
            
            if (restrictionBypassAvailable) {
                var methodName = this.getName();
                var className = this.getDeclaringClass().getName();
                
                // Log potentially restricted method invocations
                var restrictedMethods = [
                    "getPermissionFlags",
                    "setPermissionFlags",
                    "getInstalledPackages",
                    "getApplicationInfo",
                    "checkPermission"
                ];
                
                if (restrictedMethods.includes(methodName)) {
                    console.log("[RestrictionBypass] 🔍 Restricted Method Invocation:");
                    console.log("  Class: " + className);
                    console.log("  Method: " + methodName);
                    console.log("  Args Count: " + (args ? args.length : 0));
                }
            }
            
            return result;
        };
        
        console.log("[RestrictionBypass] ✅ Reflection monitoring hooks installed");
        
    } catch (e) {
        console.log("[RestrictionBypass] ❌ Failed to install reflection hooks: " + e.message);
    }
    
    // Summary
    console.log("[RestrictionBypass] 🎉 Script initialization complete!");
    if (restrictionBypassAvailable) {
        console.log("[RestrictionBypass] 🚀 Enhanced API access mode: ACTIVE");
        console.log("[RestrictionBypass] 📊 Monitoring: Permission Manager, Package Manager, System Services, Hidden APIs");
    } else {
        console.log("[RestrictionBypass] 📊 Standard monitoring mode: ACTIVE");
        console.log("[RestrictionBypass] 💡 For enhanced features, integrate RestrictionBypass library in target app");
    }
    
    // Helper function to manually trigger enhanced analysis
    Java.choose("android.app.Application", {
        onMatch: function(instance) {
            console.log("[RestrictionBypass] 📱 Application context found: " + instance.getPackageName());
            
            if (restrictionBypassAvailable) {
                // Perform enhanced analysis if RestrictionBypass is available
                setTimeout(function() {
                    console.log("[RestrictionBypass] 🔍 Performing enhanced application analysis...");
                    
                    try {
                        var packageManager = instance.getPackageManager();
                        var packageName = instance.getPackageName();
                        
                        // Get enhanced application info
                        var appInfo = packageManager.getApplicationInfo(packageName, 0);
                        console.log("[RestrictionBypass] 📊 Enhanced App Analysis Results:");
                        console.log("  Package: " + packageName);
                        console.log("  Target SDK: " + appInfo.targetSdkVersion.value);
                        console.log("  Data Dir: " + appInfo.dataDir.value);
                        console.log("  Native Lib Dir: " + appInfo.nativeLibraryDir.value);
                        
                    } catch (e) {
                        console.log("[RestrictionBypass] ❌ Enhanced analysis failed: " + e.message);
                    }
                }, 2000);
            }
        },
        onComplete: function() {
            console.log("[RestrictionBypass] ✅ Application context search complete");
        }
    });
});

console.log("[RestrictionBypass] Script loaded successfully! 🎯");
