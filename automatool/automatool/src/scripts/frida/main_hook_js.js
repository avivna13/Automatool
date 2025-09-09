/*
 * This script combines, fixes & extends a long list of other scripts, most notably including:
 *
 * - https://codeshare.frida.re/@dzonerzy/fridantiroot/
 * - https://github.com/AshenOneYe/FridaAntiRootDetection/blob/main/antiroot.js
 */


const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/data/adb/ksu",
    "/data/adb/ksud"
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu"
];



function stackTraceHere(isLog) {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new())
    if (isLog) {
        console.log(stackinfo)
    } else {
        return stackinfo
    }
}

function stackTraceNativeHere(isLog) {
    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n\t");
    console.log(backtrace)
}


function bypassJavaFileCheck() {
    var UnixFileSystem = Java.use("java.io.UnixFileSystem")
    UnixFileSystem.checkAccess.implementation = function (file, access) {

        var stack = stackTraceHere(false)

        const filename = file.getAbsolutePath();

        if (filename.indexOf("magisk") >= 0) {
            // console.log("Anti Root Detect - check file: " + filename)
            return false;
        }

        if (commonPaths.indexOf(filename) >= 0) {
            // console.log("Anti Root Detect - check file: " + filename)
            return false;
        }

        return this.checkAccess(file, access)
    }
}

function bypassNativeFileCheck() {
    var fopen = Module.findExportByName("libc.so", "fopen")
    Interceptor.attach(fopen, {
        onEnter: function (args) {
            this.inputPath = args[0].readUtf8String()
        },
        onLeave: function (retval) {
            if (retval.toInt32() != 0) {
                if (commonPaths.indexOf(this.inputPath) >= 0) {
                    // console.log("Anti Root Detect - fopen : " + this.inputPath)
                    retval.replace(ptr(0x0))
                }
            }
        }
    })

    var access = Module.findExportByName("libc.so", "access")
    Interceptor.attach(access, {
        onEnter: function (args) {
            this.inputPath = args[0].readUtf8String()
        },
        onLeave: function (retval) {
            if (retval.toInt32() == 0) {
                if (commonPaths.indexOf(this.inputPath) >= 0) {
                    // console.log("Anti Root Detect - access : " + this.inputPath)
                    retval.replace(ptr(-1))
                }
            }
        }
    })
}

function setProp() {
    var Build = Java.use("android.os.Build")
    var TAGS = Build.class.getDeclaredField("TAGS")
    TAGS.setAccessible(true)
    TAGS.set(null, "release-keys")

    var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT")
    FINGERPRINT.setAccessible(true)
    FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys")

    // Build.deriveFingerprint.inplementation = function(){
    //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
    //     console.log(ret)
    //     return ret
    // }

    var system_property_get = Module.findExportByName("libc.so", "__system_property_get")
    Interceptor.attach(system_property_get, {
        onEnter(args) {
            this.key = args[0].readCString()
            this.ret = args[1]
        },
        onLeave(ret) {
            if (this.key == "ro.build.fingerprint") {
                var tmp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
                var p = Memory.allocUtf8String(tmp)
                Memory.copy(this.ret, p, tmp.length + 1)
            }
        }
    })

}

//android.app.PackageManager
function bypassRootAppCheck() {
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
    ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (str, i) {
        // console.log(str)
        if (ROOTmanagementApp.indexOf(str) >= 0) {
            console.log("Anti Root Detect - check package : " + str)
            str = "ashen.one.ye.not.found"
        }
        return this.getPackageInfo(str, i)
    }

    //shell pm check
}

function bypassShellCheck() {
    var String = Java.use('java.lang.String')

    var ProcessImpl = Java.use("java.lang.ProcessImpl")
    ProcessImpl.start.implementation = function (cmdarray, env, dir, redirects, redirectErrorStream) {

        if (cmdarray[0] == "mount") {
            // console.log("Anti Root Detect - Shell : " + cmdarray.toString())
            arguments[0] = Java.array('java.lang.String', [String.$new("")])
            return ProcessImpl.start.apply(this, arguments)
        }

        if (cmdarray[0] == "getprop") {
            // console.log("Anti Root Detect - Shell : " + cmdarray.toString())
            const prop = [
                "ro.secure",
                "ro.debuggable"
            ];
            if (prop.indexOf(cmdarray[1]) >= 0) {
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }
        }

        if (cmdarray[0].indexOf("which") >= 0) {
            const prop = [
                "su"
            ];
            if (prop.indexOf(cmdarray[1]) >= 0) {
                // console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }
        }

        return ProcessImpl.start.apply(this, arguments)
    }
}



/**
 * Generates a random 16-character hexadecimal string, mimicking an Android ID.
 * @returns {string} A random Android ID.
 */
function generateRandomAndroidId() {
    const hexChars = "0123456789abcdef";
    let androidId = "";
    for (let i = 0; i < 16; i++) {
        const randomIndex = Math.floor(Math.random() * hexChars.length);
        androidId += hexChars[randomIndex];
    }
    return androidId;
}

function bypassRootChecks() {
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();
}


/**
 * Generates a random 16-character hexadecimal string, mimicking an Android ID.
 * @returns {string} A random Android ID.
 */
function generateRandomAndroidId() {
    const hexChars = "0123456789abcdef";
    let androidId = "";
    for (let i = 0; i < 16; i++) {
        const randomIndex = Math.floor(Math.random() * hexChars.length);
        androidId += hexChars[randomIndex];
    }
    return androidId;
}

/**
 * Sets up Frida hooks to spoof specific Android system properties.
 */
function setupSystemPropertyHooks() {

    const spoofedSettings = {
        "adb_enabled": "0",
        "development_settings_enabled": "0",
        "android_id": generateRandomAndroidId(),
        "auto_time": "1",
        "auto_time_zone": "1",
        "debug_app": null,
        "http_proxy": "0",
        "install_non_market_apps": "0",
        "bluetooth_name": "samsung",
        "wifi": "1",
        "wait_for_debugger": "0",
        "stay_on_while_plugged_in": "0",
        "wifi_on": "1",
        "mobile_data": "1",
    };

    const NameValueCache = Java.use("android.provider.Settings$NameValueCache");

    NameValueCache.getStringForUser.implementation = function (...args) {
        const settingName = args[1];
        let result;

        if (Object.prototype.hasOwnProperty.call(spoofedSettings, settingName)) {
            result = spoofedSettings[settingName];
        } else {
            result = this.getStringForUser(...args);
        }

        const logInfo = {
            caller: "Setting",
            className: "android.provider.Settings",
            methodName: "getStringForUser",
            returnValue: result,
            arguments: settingName,
        };

        console.log(JSON.stringify(logInfo));

        return result;
    };
}

function VPNHook() {
    const BANNED_INTERFACES = new Set([
        'tun0',
        'ppp0',
        'pppp'
    ]);
    const SPOOFED_NAME = 'dummy0';

    const NetworkInterface = Java.use('java.net.NetworkInterface');

    NetworkInterface.getName.implementation = function () {
        const realName = this.getName();

        if (BANNED_INTERFACES.has(realName)) {
            console.log(`[NetworkInterface] Spoofing detected interface '${realName}' with '${SPOOFED_NAME}'`);
            return SPOOFED_NAME;
        }

        return realName;
    };
}


function bypassNetworkConnectionChecks(verbose = false) {
    const ConnectivityManager = Java.use("android.net.ConnectivityManager");
    const NetworkInfo = Java.use("android.net.NetworkInfo");
    const DetailedState = Java.use("android.net.NetworkInfo$DetailedState");
    const NetworkCapabilities = Java.use("android.net.NetworkCapabilities");

    const FAKE_CONNECTION_TYPE = 0; // TYPE_MOBILE
    const FAKE_NETWORK_SUBTYPE = 13; // NETWORK_TYPE_LTE
    const TRANSPORT_CELLULAR = 0;

    function hookGetActiveNetworkInfo() {
        ConnectivityManager.getActiveNetworkInfo.implementation = function () {
            if (verbose) {
                console.log(`[getActiveNetworkInfo] Bypassing check...`);
            }

            const fakeNetworkInfo = NetworkInfo.$new(
                FAKE_CONNECTION_TYPE,
                FAKE_NETWORK_SUBTYPE,
                "MOBILE",
                "LTE"
            );

            fakeNetworkInfo.mIsAvailable.value = true;
            fakeNetworkInfo.setDetailedState(DetailedState.CONNECTED.value, null, null);

            return fakeNetworkInfo;
        };
    }

    function hookHasTransport() {
        NetworkCapabilities.hasTransport.implementation = function (transportType) {

            if (verbose) {
                console.log(`[hasTransport] App checking for transport type: ${transportType}`);
                console.log(`\tReturning spoofed result: true`);
            }

            return true;
        };
    }

    // --- Apply Hooks ---
    console.log("🚀 Applying network connection bypass hooks...");
    hookGetActiveNetworkInfo();
    hookHasTransport();
}

function installReferrerHook(utm_source, utm_medium) {
    try {
        let com_android_installreferrer_api_ReferrerDetails = Java.use("com.android.installreferrer.api.ReferrerDetails");
        com_android_installreferrer_api_ReferrerDetails.$init.overload("android.os.Bundle").implementation = function (arg0) {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.<init>: arg0=${arg0}`);
            this["$init"](arg0);
            let installReferrer = `utm_source=${utm_source}&utm_medium=${utm_medium}`; // This is the important part.

            let time = new Date().getTime() / 1000;
            let installBeginTimestampSeconds = time - 30;
            let installBeginTimestampServerSeconds = time - 31;
            let referrerClickTimestampSeconds = time - 60;
            let referrerClickTimestampServerSeconds = time - 59;

            this.mOriginalBundle.value.putString("install_referrer", installReferrer);
            this.mOriginalBundle.value.putString("install_version", "1.0");
            this.mOriginalBundle.value.putLong("install_begin_timestamp_seconds", installBeginTimestampSeconds);
            this.mOriginalBundle.value.putLong("install_begin_timestamp_server_seconds", installBeginTimestampServerSeconds);
            this.mOriginalBundle.value.putLong("referrer_click_timestamp_seconds", referrerClickTimestampSeconds);
            this.mOriginalBundle.value.putLong("referrer_click_timestamp_server_seconds", referrerClickTimestampServerSeconds);
        };
    }
    catch (error) {
        console.log(error.message);
    }

}

function pairipHook() {
    try {

        let ResponseValidator = Java.use('com.pairip.licensecheck.ResponseValidator');
        ResponseValidator.validateResponse.overload("android.os.Bundle", "java.lang.String").implementation = function (arg0, arg1) {
            console.log(`[->] validateResponse: arg0=${arg0}, arg1=${arg1}`);
            console.log("Bypassing validateResponse by returning immideately...");
            return
        };

        let LicenseClient = Java.use('com.pairip.licensecheck.LicenseClient');
        LicenseClient.processResponse.overload("int", "android.os.Bundle").implementation = function (arg0, arg1) {
            console.log(`[->] processResponse: arg0=${arg0}, arg1=${arg1}`);
            console.log(`Bypassing processResponse by changing [arg0] from ${arg0} to 0`);
            this['processResponse'](0, arg1);
        };
    }
    catch (error) {
        console.log(error.message);
    }
}

function ssl_unpinning_multiple() {
    setTimeout(function () {
        // Java.perform(function () {
        console.log('');
        console.log('======');
        console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
        console.log('======');

        var errDict = {};

        // TrustManager (Android < 7) //
        ////////////////////////////////
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'dev.asd.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        // Prepare the TrustManager array to pass to SSLContext.init()
        var TrustManagers = [TrustManager.$new()];
        // Get a handle on the init() on the SSLContext class
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        try {
            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                console.log('[+] Bypassing Trustmanager (Android < 7) pinner');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch (err) {
            console.log('[-] TrustManager (Android < 7) pinner not found');
            //console.log(err);
        }




        // OkHTTPv3 (quadruple bypass) //
        /////////////////////////////////
        try {
            // Bypass OkHTTPv3 {1}
            var okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {1}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] OkHTTPv3 {1} pinner not found');
            //console.log(err);
            errDict[err] = ['okhttp3.CertificatePinner', 'check'];
        }
        try {
            // Bypass OkHTTPv3 {2}
            // This method of CertificatePinner.check is deprecated but could be found in some old Android apps
            var okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {2}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] OkHTTPv3 {2} pinner not found');
            //console.log(err);
            //errDict[err] = ['okhttp3.CertificatePinner', 'check'];
        }
        try {
            // Bypass OkHTTPv3 {3}
            var okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
            okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {3}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] OkHTTPv3 {3} pinner not found');
            //console.log(err);
            errDict[err] = ['okhttp3.CertificatePinner', 'check'];
        }
        try {
            // Bypass OkHTTPv3 {4}
            var okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
            //okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
            okhttp3_Activity_4.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (a, b) {
                console.log('[+] Bypassing OkHTTPv3 {4}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] OkHTTPv3 {4} pinner not found');
            //console.log(err);
            errDict[err] = ['okhttp3.CertificatePinner', 'check$okhttp'];
        }



        // Trustkit (triple bypass) //
        //////////////////////////////
        try {
            // Bypass Trustkit {1}
            var trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                console.log('[+] Bypassing Trustkit {1}: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Trustkit {1} pinner not found');
            //console.log(err);
            errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
        }
        try {
            // Bypass Trustkit {2}
            var trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing Trustkit {2}: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Trustkit {2} pinner not found');
            //console.log(err);
            errDict[err] = ['com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify'];
        }
        try {
            // Bypass Trustkit {3}
            var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
            trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
                console.log('[+] Bypassing Trustkit {3}');
            };
        } catch (err) {
            console.log('[-] Trustkit {3} pinner not found');
            //console.log(err);
            errDict[err] = ['com.datatheorem.android.trustkit.pinning.PinningTrustManager', 'checkServerTrusted'];
        }




        // TrustManagerImpl (Android > 7) //
        ////////////////////////////////////
        try {
            // Bypass TrustManagerImpl (Android > 7) {1}
            var array_list = Java.use("java.util.ArrayList");
            var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check for: ' + host);
                return array_list.$new();
            };
        } catch (err) {
            console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'checkTrustedRecursive'];
        }
        try {
            // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
            var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl_Activity_2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check for: ' + host);
                return untrustedChain;
            };
        } catch (err) {
            console.log('[-] TrustManagerImpl (Android > 7) verifyChain check not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.TrustManagerImpl', 'verifyChain'];
        }





        // Appcelerator Titanium PinningTrustManager //
        ///////////////////////////////////////////////
        try {
            var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            appcelerator_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                console.log('[+] Bypassing Appcelerator PinningTrustManager');
                return;
            };
        } catch (err) {
            console.log('[-] Appcelerator PinningTrustManager pinner not found');
            //console.log(err);
            errDict[err] = ['appcelerator.https.PinningTrustManager', 'checkServerTrusted'];
        }




        // Fabric PinningTrustManager //
        ////////////////////////////////
        try {
            var fabric_PinningTrustManager = Java.use('io.fabric.sdk.android.services.network.PinningTrustManager');
            fabric_PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                console.log('[+] Bypassing Fabric PinningTrustManager');
                return;
            };
        } catch (err) {
            console.log('[-] Fabric PinningTrustManager pinner not found');
            //console.log(err);
            errDict[err] = ['io.fabric.sdk.android.services.network.PinningTrustManager', 'checkServerTrusted'];
        }




        // OpenSSLSocketImpl Conscrypt (double bypass) //
        /////////////////////////////////////////////////
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {1}');
            };
        } catch (err) {
            console.log('[-] OpenSSLSocketImpl Conscrypt {1} pinner not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];
        }
        try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certChain, authMethod) {
                console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
            };
        } catch (err) {
            console.log('[-] OpenSSLSocketImpl Conscrypt {2} pinner not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.OpenSSLSocketImpl', 'verifyCertificateChain'];
        }




        // OpenSSLEngineSocketImpl Conscrypt //
        ///////////////////////////////////////
        try {
            var OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
                console.log('[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
            };
        } catch (err) {
            console.log('[-] OpenSSLEngineSocketImpl Conscrypt pinner not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.OpenSSLEngineSocketImpl', 'verifyCertificateChain'];
        }




        // OpenSSLSocketImpl Apache Harmony //
        //////////////////////////////////////
        try {
            var OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                console.log('[+] Bypassing OpenSSLSocketImpl Apache Harmony');
            };
        } catch (err) {
            console.log('[-] OpenSSLSocketImpl Apache Harmony pinner not found');
            //console.log(err);
            errDict[err] = ['org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl', 'verifyCertificateChain'];
        }




        // PhoneGap sslCertificateChecker //
        ////////////////////////////////////
        try {
            var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
            phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                console.log('[+] Bypassing PhoneGap sslCertificateChecker: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] PhoneGap sslCertificateChecker pinner not found');
            //console.log(err);
            errDict[err] = ['nl.xservices.plugins.sslCertificateChecker', 'execute'];
        }




        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
        ////////////////////////////////////////////////////////////////////
        try {
            // Bypass IBM MobileFirst {1}
            var WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
                console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + cert);
                return;
            };
        } catch (err) {
            console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
        }
        try {
            // Bypass IBM MobileFirst {2}
            var WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
                console.log('[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: ' + cert);
                return;
            };
        } catch (err) {
            console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.api.WLClient', 'pinTrustedCertificatePublicKey'];
        }




        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
        ///////////////////////////////////////////////////////////////////////////////////////////////////////
        try {
            // Bypass IBM WorkLight {1}
            var worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
        }
        try {
            // Bypass IBM WorkLight {2}
            var worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
        }
        try {
            // Bypass IBM WorkLight {3}
            var worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
        }
        try {
            // Bypass IBM WorkLight {4}
            var worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
            worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                console.log('[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning', 'verify'];
        }




        // Conscrypt CertPinManager //
        //////////////////////////////
        try {
            var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
            conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Conscrypt CertPinManager pinner not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'checkChainPinning'];
        }




        // Conscrypt CertPinManager (Legacy) //
        ///////////////////////////////////////
        try {
            var legacy_conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
            legacy_conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing Conscrypt CertPinManager (Legacy): ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Conscrypt CertPinManager (Legacy) pinner not found');
            //console.log(err);
            errDict[err] = ['com.android.org.conscrypt.CertPinManager', 'isChainValid'];
        }




        // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            var cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
            cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing CWAC-Netsecurity CertPinManager: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] CWAC-Netsecurity CertPinManager pinner not found');
            //console.log(err);
            errDict[err] = ['com.commonsware.cwac.netsecurity.conscrypt.CertPinManager', 'isChainValid'];
        }




        // Worklight Androidgap WLCertificatePinningPlugin //
        /////////////////////////////////////////////////////
        try {
            var androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
                console.log('[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found');
            //console.log(err);
            errDict[err] = ['com.worklight.androidgap.plugin.WLCertificatePinningPlugin', 'execute'];
        }




        // Netty FingerprintTrustManagerFactory //
        //////////////////////////////////////////
        try {
            var netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            //NOTE: sometimes this below implementation could be useful 
            //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                console.log('[+] Bypassing Netty FingerprintTrustManagerFactory');
            };
        } catch (err) {
            console.log('[-] Netty FingerprintTrustManagerFactory pinner not found');
            //console.log(err);
            errDict[err] = ['io.netty.handler.ssl.util.FingerprintTrustManagerFactory', 'checkTrusted'];
        }




        // Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
        ////////////////////////////////////////////////////////////
        try {
            // Bypass Squareup CertificatePinner  {1}
            var Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing Squareup CertificatePinner {1}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Squareup CertificatePinner {1} pinner not found');
            //console.log(err);
            errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
        }
        try {
            // Bypass Squareup CertificatePinner {2}
            var Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
            Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                console.log('[+] Bypassing Squareup CertificatePinner {2}: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Squareup CertificatePinner {2} pinner not found');
            //console.log(err);
            errDict[err] = ['com.squareup.okhttp.CertificatePinner', 'check'];
        }




        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
        /////////////////////////////////////////////////////////////
        try {
            // Bypass Squareup OkHostnameVerifier {1}
            var Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing Squareup OkHostnameVerifier {1}: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Squareup OkHostnameVerifier check not found');
            //console.log(err);
            errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
        }
        try {
            // Bypass Squareup OkHostnameVerifier {2}
            var Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
            Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                console.log('[+] Bypassing Squareup OkHostnameVerifier {2}: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Squareup OkHostnameVerifier check not found');
            //console.log(err);
            errDict[err] = ['com.squareup.okhttp.internal.tls.OkHostnameVerifier', 'verify'];
        }




        // Android WebViewClient (quadruple bypass) //
        //////////////////////////////////////////////
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            var AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                console.log('[+] Bypassing Android WebViewClient check {1}');
            };
        } catch (err) {
            console.log('[-] Android WebViewClient {1} check not found');
            //console.log(err)
            errDict[err] = ['android.webkit.WebViewClient', 'onReceivedSslError'];
        }
        // Not working properly temporarily disused
        //try {
        //	// Bypass WebViewClient {2}
        //	var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
        //	AndroidWebViewClient_Activity_2.onReceivedHttpError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceResponse').implementation = function(obj1, obj2, obj3) {
        //		console.log('[+] Bypassing Android WebViewClient check {2}');
        //	};
        //} catch (err) {
        //	console.log('[-] Android WebViewClient {2} check not found');
        //	//console.log(err)
        //	errDict[err] = ['android.webkit.WebViewClient', 'onReceivedHttpError'];
        //}
        try {
            // Bypass WebViewClient {3}
            var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
            //AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(obj1, obj2, obj3, obj4) {
            AndroidWebViewClient_Activity_3.onReceivedError.implementation = function (view, errCode, description, failingUrl) {
                console.log('[+] Bypassing Android WebViewClient check {3}');
            };
        } catch (err) {
            console.log('[-] Android WebViewClient {3} check not found');
            //console.log(err)
            errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
        }
        try {
            // Bypass WebViewClient {4}
            var AndroidWebViewClient_Activity_4 = Java.use('android.webkit.WebViewClient');
            AndroidWebViewClient_Activity_4.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
                console.log('[+] Bypassing Android WebViewClient check {4}');
            };
        } catch (err) {
            console.log('[-] Android WebViewClient {4} check not found');
            //console.log(err)
            errDict[err] = ['android.webkit.WebViewClient', 'onReceivedError'];
        }




        // Apache Cordova WebViewClient //
        //////////////////////////////////
        try {
            var CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
            CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
                console.log('[+] Bypassing Apache Cordova WebViewClient check');
                obj3.proceed();
            };
        } catch (err) {
            console.log('[-] Apache Cordova WebViewClient check not found');
            //console.log(err);
        }




        // Boye AbstractVerifier //
        ///////////////////////////
        try {
            var boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
            boye_AbstractVerifier.verify.implementation = function (host, ssl) {
                console.log('[+] Bypassing Boye AbstractVerifier check for: ' + host);
            };
        } catch (err) {
            console.log('[-] Boye AbstractVerifier check not found');
            //console.log(err);
            errDict[err] = ['ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier', 'verify'];
        }



        // Apache AbstractVerifier (quadruple bypass) //
        ////////////////////////////////////////////////
        try {
            var apache_AbstractVerifier_1 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            apache_AbstractVerifier_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
                console.log('[+] Bypassing Apache AbstractVerifier {1} check for: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Apache AbstractVerifier {1} check not found');
            //console.log(err);
            errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
        }
        try {
            var apache_AbstractVerifier_2 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            apache_AbstractVerifier_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
                console.log('[+] Bypassing Apache AbstractVerifier {2} check for: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Apache AbstractVerifier {2} check not found');
            //console.log(err);
            errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
        }
        try {
            var apache_AbstractVerifier_3 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            apache_AbstractVerifier_3.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
                console.log('[+] Bypassing Apache AbstractVerifier {3} check for: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Apache AbstractVerifier {3} check not found');
            //console.log(err);
            errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
        }
        try {
            var apache_AbstractVerifier_4 = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            apache_AbstractVerifier_4.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (a, b, c, d) {
                console.log('[+] Bypassing Apache AbstractVerifier {4} check for: ' + a);
                return;
            };
        } catch (err) {
            console.log('[-] Apache AbstractVerifier {4} check not found');
            //console.log(err);
            errDict[err] = ['org.apache.http.conn.ssl.AbstractVerifier', 'verify'];
        }




        // Chromium Cronet //
        /////////////////////
        try {
            var CronetEngineBuilderImpl_Activity = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
            // Setting argument to TRUE (default is TRUE) to disable Public Key pinning for local trust anchors
            CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.overload('boolean').implementation = function (a) {
                console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                var cronet_obj_1 = CronetEngine_Activity.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                return cronet_obj_1;
            };
            // Bypassing Chromium Cronet pinner
            CronetEngine_Activity.addPublicKeyPins.overload('java.lang.String', 'java.util.Set', 'boolean', 'java.util.Date').implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
                var cronet_obj_2 = CronetEngine_Activity.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
                return cronet_obj_2;
            };
        } catch (err) {
            console.log('[-] Chromium Cronet pinner not found')
            //console.log(err);
        }




        // Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin (double bypass) //
        //////////////////////////////////////////////////////////////////////////////////////////////
        try {
            // Bypass HttpCertificatePinning.check {1}
            var HttpCertificatePinning_Activity = Java.use('diefferson.http_certificate_pinning.HttpCertificatePinning');
            HttpCertificatePinning_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                console.log('[+] Bypassing Flutter HttpCertificatePinning : ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Flutter HttpCertificatePinning pinner not found');
            //console.log(err);
            errDict[err] = ['diefferson.http_certificate_pinning.HttpCertificatePinning', 'checkConnexion'];
        }
        try {
            // Bypass SslPinningPlugin.check {2}
            var SslPinningPlugin_Activity = Java.use('com.macif.plugin.sslpinningplugin.SslPinningPlugin');
            SslPinningPlugin_Activity.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                console.log('[+] Bypassing Flutter SslPinningPlugin: ' + a);
                return true;
            };
        } catch (err) {
            console.log('[-] Flutter SslPinningPlugin pinner not found');
            //console.log(err);
            errDict[err] = ['com.macif.plugin.sslpinningplugin.SslPinningPlugin', 'checkConnexion'];
        }




        // Unusual/obfuscated pinners bypass //
        ///////////////////////////////////////
        try {
            // Iterating all caught pinner errors and try to overload them 
            for (var key in errDict) {
                var errStr = key;
                var targetClass = errDict[key][0]
                var targetFunc = errDict[key][1]
                var retType = Java.use(targetClass)[targetFunc].returnType.type;
                //console.log("errDict content: "+errStr+" "+targetClass+"."+targetFunc);
                if (String(errStr).includes('.overload')) {
                    overloader(errStr, targetClass, targetFunc, retType);
                }
            }
        } catch (err) {
            //console.log('[-] The pinner "'+targetClass+'.'+targetFunc+'" is not unusual/obfuscated, skipping it..');
            //console.log(err);
        }




        // Dynamic SSLPeerUnverifiedException Bypasser                               //
        // An useful technique to bypass SSLPeerUnverifiedException failures raising //
        // when the Android app uses some uncommon SSL Pinning methods or an heavily //
        // code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
        ///////////////////////////////////////////////////////////////////////////////
        try {
            var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
            UnverifiedCertError.$init.implementation = function (reason) {
                try {
                    var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    var exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    // Retrieve the method raising the SSLPeerUnverifiedException
                    var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                    var className = callingFunctionStack.getClassName();
                    var methodName = callingFunctionStack.getMethodName();
                    var callingClass = Java.use(className);
                    var callingMethod = callingClass[methodName];
                    console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred related to the method "' + className + '.' + methodName + '"\x1b[0m');
                    //console.log("Stacktrace details:\n"+stackTrace);
                    // Checking if the SSLPeerUnverifiedException was generated by an usually negligible (not blocking) method
                    if (className == 'com.android.org.conscrypt.ActiveSession' || className == 'com.google.android.gms.org.conscrypt.ActiveSession') {
                        throw 'Reason: skipped SSLPeerUnverifiedException bypass since the exception was raised from a (usually) non blocking method on the Android app';
                    }
                    else {
                        console.log('\x1b[34m[!] Starting to dynamically circumvent the SSLPeerUnverifiedException for the method "' + className + '.' + methodName + '"...\x1b[0m');
                        var retTypeName = callingMethod.returnType.type;
                        // Skip it when the calling method was already bypassed with Frida
                        if (!(callingMethod.implementation)) {
                            // Trying to bypass (via implementation) the SSLPeerUnverifiedException if due to an uncommon SSL Pinning method
                            callingMethod.implementation = function () {
                                console.log('\x1b[34m[+] Bypassing the unusual/obfuscated pinner "' + className + '.' + methodName + '" via Frida function implementation\x1b[0m');
                                returner(retTypeName);
                            }
                        }
                    }
                } catch (err2) {
                    // Dynamic circumvention via function implementation does not works, then trying via function overloading
                    if (String(err2).includes('.overload')) {
                        overloader(err2, className, methodName, retTypeName);
                    } else {
                        if (String(err2).includes('SSLPeerUnverifiedException')) {
                            console.log('\x1b[36m[-] Failed to dynamically circumvent SSLPeerUnverifiedException -> ' + err2 + '\x1b[0m');
                        } else {
                            //console.log('\x1b[36m[-] Another kind of exception raised during overloading  -> '+err2+'\x1b[0m');
                        }
                    }
                }
                //console.log('\x1b[36m[+] SSLPeerUnverifiedException hooked\x1b[0m');
                return this.$init(reason);
            };
        } catch (err1) {
            //console.log('\x1b[36m[-] SSLPeerUnverifiedException not found\x1b[0m');
            //console.log('\x1b[36m'+err1+'\x1b[0m');
        }


        // });

    }, 0);

}

function print_logs() {
    // Java.perform(function () {
    var Log = Java.use("android.util.Log");

    Log.d.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (a, b, c) {
        console.log("[LOG] Log.d(" + a.toString() + ", " + b.toString() + ")");
        return this.d(a, b, c);
    };

    Log.v.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (a, b, c) {
        console.log("[LOG] Log.v(" + a.toString() + ", " + b.toString() + ")");
        return this.v(a, b, c);
    };

    Log.i.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (a, b, c) {
        console.log("[LOG] Log.i(" + a.toString() + ", " + b.toString() + ")");
        return this.i(a, b, c);
    };

    Log.e.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (a, b, c) {
        console.log("[LOG] Log.e(" + a.toString() + ", " + b.toString() + ")");
        return this.e(a, b, c);
    };

    Log.w.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (a, b, c) {
        console.log("[LOG] Log.w(" + a.toString() + ", " + b.toString() + ")");
        return this.w(a, b, c);
    };

    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log("[LOG] Log.d(" + a.toString() + ", " + b.toString() + ")");
        return this.d(a, b);
    };

    Log.v.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log("[LOG] Log.v(" + a.toString() + ", " + b.toString() + ")");
        return this.v(a, b);
    };

    Log.i.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log("[LOG] Log.i(" + a.toString() + ", " + b.toString() + ")");
        return this.i(a, b);
    };
    Log.e.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log("[LOG] Log.e(" + a.toString() + ", " + b.toString() + ")");
        return this.e(a, b);
    };
    Log.w.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        console.log("[LOG] Log.w(" + a.toString() + ", " + b.toString() + ")");
        return this.w(a, b);
    };
    // });
}

function android_crypto_intercept() {
    const MODE = {
        KeyGenerator: true,
        KeyPairGenerator: true,
        SecretKeySpec: true,
        MessageDigest: true,
        SecretKeyFactory: true,
        Signature: true,
        Cipher: true,
        Mac: true,
        KeyGenParameterSpec: true,
        IvParameterSpec: true
    };


    let index = 0; // color index
    const STRING = Java.use("java.lang.String");
    const BASE64 = Java.use("java.util.Base64");
    const COLORS = {
        red: '\x1b[31m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        blue: '\x1b[34m',
        magenta: '\x1b[35m',
        cyan: '\x1b[36m',
        reset: '\x1b[0m'
    };

    const randomColor = () => {
        const colorKeys = Object.keys(COLORS).filter(key => key !== "reset" && key !== "red");
        index = (index + 1) % colorKeys.length;
        return COLORS[colorKeys[index]];
    }

    const bytesToString = (bytes) => {
        return bytes === null ? null : STRING.$new(bytes).toString();
    }

    const bytesToBase64 = (bytes) => {
        if (bytes !== null) {
            try {
                return BASE64.getEncoder().encodeToString(bytes);
            } catch {
                return BASE64.getEncoder().encodeToString([bytes & 0xff]);
            }
        }
        return null;
    }

    const Base64ToHex = (base64) => {
        const bytes = BASE64.getDecoder().decode(base64);
        let hexData = "";
        for (let i = 0; i < bytes.length; i++) {
            let value = bytes[i].toString(16);
            if (value.length % 2 === 1) {
                value = "0" + value
            }
            hexData += value
        }
        return hexData;
    }

    const showVariable = (module, items, colorKey, hexValue = false) => {
        console.log(`${colorKey}[+] onEnter: ${module}${COLORS.reset}`);
        for (let i = 0; i < items.length; i++) {
            console.log(`${colorKey}  --> [${i}] ${items[i].key}: ${items[i].value}${COLORS.reset}`);

            // Hex
            if (items[i].key.includes("Base64") && items[i].value !== null) {
                const key = items[i].key.replace("Base64", "HEX");
                const value = Base64ToHex(items[i].value);
                if ((!value.includes("-") && [32, 40, 48, 64].includes(value.length)) || hexValue) {
                    console.log(`${colorKey}  --> [${i}] ${key}: ${value}${COLORS.reset}`);
                }
            }
        }
        console.log(`${colorKey}[-] onLeave: ${module}${COLORS.reset}`);
    }


    setTimeout(function () {
        console.log("---");
        console.log("Capturing Android app...");

        if (Java.available) {
            console.log("[*] Java available");
            Java.perform(function () {

                if (MODE.KeyGenerator) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.KeyGenerator");
                    const keyGenerator = Java.use("javax.crypto.KeyGenerator");

                    keyGenerator.generateKey.implementation = function () {
                        showVariable("keyGenerator.generateKey", [], colorKey);
                        return this.generateKey();
                    };

                    keyGenerator.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("keyGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    keyGenerator.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("keyGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    keyGenerator.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("keyGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                }

                if (MODE.KeyPairGenerator) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: java.security.KeyPairGenerator");
                    const keyPairGenerator = Java.use("java.security.KeyPairGenerator");
                    keyPairGenerator.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("keyPairGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    keyPairGenerator.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("keyPairGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    keyPairGenerator.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("keyPairGenerator.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };
                }

                if (MODE.SecretKeySpec) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.spec.SecretKeySpec");
                    const secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                    secretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, cipher) {
                        const keyBase64 = bytesToBase64(key);
                        const keyString = bytesToString(key);
                        showVariable("secretKeySpec.init", [
                            { key: "Key Base64", value: keyBase64 },
                            { key: "Key String", value: keyString },
                            { key: "Algorithm", value: cipher }
                        ], colorKey);
                        return secretKeySpec.$init.overload("[B", "java.lang.String").call(this, key, cipher);
                    }
                }

                if (MODE.MessageDigest) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: java.security.MessageDigest");
                    const messageDigest = Java.use("java.security.MessageDigest");
                    messageDigest.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("messageDigest.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    messageDigest.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("messageDigest.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    messageDigest.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("messageDigest.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    messageDigest.update.overload("[B").implementation = function (input) {
                        const inputBase64 = bytesToBase64(input);
                        const inputString = bytesToString(input);
                        showVariable("messageDigest.update", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString }
                        ], colorKey);
                        return this.update.overload("[B").call(this, input);
                    };

                    messageDigest.digest.overload().implementation = function () {
                        const output = messageDigest.digest.overload().call(this);
                        const outputBase64 = bytesToBase64(output);
                        const outputString = bytesToString(output);
                        showVariable("messageDigest.digest", [
                            { key: "Output Base64", value: outputBase64 },
                            { key: "Output String", value: outputString },
                            { key: "Algorithm", value: this.getAlgorithm() }
                        ], colorKey);
                        return output;
                    };

                    /*
                    messageDigest.digest.overload("[B").implementation = function (input) {
                        const inputBase64 = bytesToBase64(input);
                        const inputString = bytesToString(input);
                        showVariable("messageDigest.digest", [
                            {key: "Input Base64", value: inputBase64},
                            {key: "Input String", value: inputString},
                            {key: "Algorithm", value: this.getAlgorithm()}
                        ], colorKey);
                        return this.digest.overload("[B").call(this, input);
                    };

                    messageDigest.digest.overload("[B", "int", "int").implementation = function (input, offset, len) {
                        const inputBase64 = bytesToBase64(input);
                        const inputString = bytesToString(input);
                        showVariable("messageDigest.digest", [
                            {key: "Input Base64", value: inputBase64},
                            {key: "Input String", value: inputString},
                            {key: "Algorithm", value: this.getAlgorithm()},
                            {key: "Offset", value: offset},
                            {key: "Length", value: len}
                        ], colorKey);
                        return this.digest.overload("[B", "int", "int").call(this, input, offset, len);
                    };
                    */

                }

                if (MODE.SecretKeyFactory) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.SecretKeyFactory");
                    const secretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
                    secretKeyFactory.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("secretKeyFactory.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    secretKeyFactory.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("secretKeyFactory.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    secretKeyFactory.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("secretKeyFactory.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };
                }

                if (MODE.Signature) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: java.security.Signature");
                    const signature = Java.use("java.security.Signature");
                    signature.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("signature.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    signature.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("signature.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    signature.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("signature.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };
                }

                if (MODE.Cipher) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.Cipher");
                    const cipher = Java.use("javax.crypto.Cipher");
                    cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
                        showVariable("cipher.init", [
                            { key: "Key", value: bytesToBase64(key.getEncoded()) },
                            { key: "Opmode", value: this.getOpmodeString(opmode) },
                            { key: "Algorithm", value: this.getAlgorithm() }
                        ], colorKey);
                        this.init.overload("int", "java.security.Key").call(this, opmode, key);
                    }

                    cipher.init.overload("int", "java.security.cert.Certificate").implementation = function (opmode, certificate) {
                        showVariable("cipher.init", [
                            { key: "Certificate", value: bytesToBase64(certificate.getEncoded()) },
                            { key: "Opmode", value: this.getOpmodeString(opmode) },
                            { key: "Algorithm", value: this.getAlgorithm() }
                        ], colorKey);
                        this.init.overload("int", "java.security.cert.Certificate").call(this, opmode, certificate);
                    }

                    cipher.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters").implementation = function (opmode, key, algorithmParameter) {
                        showVariable("cipher.init", [
                            { key: "Key", value: bytesToBase64(key.getEncoded()) },
                            { key: "Opmode", value: this.getOpmodeString(opmode) },
                            { key: "Algorithm", value: this.getAlgorithm() }
                        ], colorKey);
                        this.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters").call(this, opmode, key, algorithmParameter);
                    }

                    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, algorithmParameter) {
                        showVariable("cipher.init", [
                            { key: "Key", value: bytesToBase64(key.getEncoded()) },
                            { key: "Opmode", value: this.getOpmodeString(opmode) },
                            { key: "Algorithm", value: this.getAlgorithm() }
                        ], colorKey);
                        this.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, opmode, key, algorithmParameter);
                    }

                    cipher.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("cipher.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("cipher.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    cipher.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("cipher.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    cipher.doFinal.overload("[B").implementation = function (arg0) {
                        const inputBase64 = bytesToBase64(arg0);
                        const inputString = bytesToString(arg0);
                        const output = this.doFinal.overload("[B").call(this, arg0);
                        const outputBase64 = bytesToBase64(output);
                        showVariable("cipher.doFinal", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString },
                            { key: "Output Base64", value: outputBase64 }
                        ], colorKey);
                        return output;
                    };


                    cipher.doFinal.overload("[B", "int").implementation = function (arg0, arg1) {
                        const inputBase64 = bytesToBase64(arg0);
                        const inputString = bytesToString(arg0);
                        const output = this.doFinal.overload("[B", "int").call(this, arg0, arg1);
                        const outputBase64 = bytesToBase64(output);
                        showVariable("cipher.doFinal", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString },
                            { key: "Output Base64", value: outputBase64 }
                        ], colorKey);
                        return output;
                    }

                    cipher.doFinal.overload("[B", "int", "int").implementation = function (arg0, arg1, arg2) {
                        const inputBase64 = bytesToBase64(arg0);
                        const inputString = bytesToString(arg0);
                        const output = this.doFinal.overload("[B", "int", "int").call(this, arg0, arg1, arg2);
                        const outputBase64 = bytesToBase64(output);
                        showVariable("cipher.doFinal", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString },
                            { key: "Output Base64", value: outputBase64 }
                        ], colorKey);
                        return output;
                    }

                    cipher.doFinal.overload("[B", "int", "int", "[B").implementation = function (arg0, arg1, arg2, arg3) {
                        const inputBase64 = bytesToBase64(arg0);
                        const inputString = bytesToString(arg0);
                        const output = this.doFinal.overload("[B", "int", "int", "[B").call(this, arg0, arg1, arg2, arg3);
                        const outputBase64 = bytesToBase64(output);
                        showVariable("cipher.doFinal", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString },
                            { key: "Output Base64", value: outputBase64 }
                        ], colorKey);
                        return output;
                    }

                    cipher.doFinal.overload("[B", "int", "int", "[B", "int").implementation = function (arg0, arg1, arg2, arg3, arg4) {
                        const inputBase64 = bytesToBase64(arg0);
                        const inputString = bytesToString(arg0);
                        const output = this.doFinal.overload("[B", "int", "int", "[B", "int").call(this, arg0, arg1, arg2, arg3, arg4);
                        const outputBase64 = bytesToBase64(output);
                        showVariable("cipher.doFinal", [
                            { key: "Input Base64", value: inputBase64 },
                            { key: "Input String", value: inputString },
                            { key: "Output Base64", value: outputBase64 }
                        ], colorKey);
                        return output;
                    }
                }

                if (MODE.Mac) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.Mac");
                    const mac = Java.use("javax.crypto.Mac");
                    mac.getInstance.overload("java.lang.String").implementation = function (arg0) {
                        showVariable("mac.getInstance", [
                            { key: "Algorithm", value: arg0 }
                        ], colorKey);
                        return this.getInstance(arg0);
                    };

                    mac.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                        showVariable("mac.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };

                    mac.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                        showVariable("mac.getInstance", [
                            { key: "Algorithm", value: arg0 },
                            { key: "Provider", value: arg1 }
                        ], colorKey);
                        return this.getInstance(arg0, arg1);
                    };
                }

                if (MODE.KeyGenParameterSpec) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: android.security.keystore.KeyGenParameterSpec$Builder");
                    const useKeyGen = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
                    useKeyGen.$init.overload("java.lang.String", "int").implementation = function (keyStoreAlias, purpose) {
                        let purposeStr = "";
                        if (purpose === 1) {
                            purposeStr = "encrypt";
                        } else if (purpose === 2) {
                            purposeStr = "decrypt";
                        } else if (purpose === 3) {
                            purposeStr = "decrypt|encrypt";
                        } else if (purpose === 4) {
                            purposeStr = "sign";
                        } else if (purpose === 8) {
                            purposeStr = "verify";
                        } else {
                            purposeStr = purpose;
                        }

                        showVariable("KeyGenParameterSpec.init", [
                            { key: "KeyStoreAlias", value: keyStoreAlias },
                            { key: "Purpose", value: purposeStr }
                        ], colorKey);
                        return useKeyGen.$init.overload("java.lang.String", "int").call(this, keyStoreAlias, purpose);
                    }

                    useKeyGen.setBlockModes.implementation = function (modes) {
                        showVariable("KeyGenParameterSpec.setBlockModes", [
                            { key: "BlockMode", value: modes.toString() }
                        ], colorKey);
                        return useKeyGen.setBlockModes.call(this, modes);
                    }

                    useKeyGen.setDigests.implementation = function (digests) {
                        showVariable("KeyGenParameterSpec.setDigests", [
                            { key: "Digests", value: digests.toString() }
                        ], colorKey);
                        return useKeyGen.setDigests.call(this, digests);
                    }

                    useKeyGen.setKeySize.implementation = function (keySize) {
                        showVariable("KeyGenParameterSpec.setKeySize", [
                            { key: "KeySize", value: keySize }
                        ], colorKey);
                        return useKeyGen.setKeySize.call(this, keySize);
                    }

                    useKeyGen.setEncryptionPaddings.implementation = function (paddings) {
                        showVariable("KeyGenParameterSpec.setEncryptionPaddings", [
                            { key: "Paddings", value: paddings.toString() }
                        ], colorKey);
                        return useKeyGen.setEncryptionPaddings.call(this, paddings);
                    }

                    useKeyGen.setSignaturePaddings.implementation = function (paddings) {
                        showVariable("KeyGenParameterSpec.setSignaturePaddings", [
                            { key: "Paddings", value: paddings.toString() }
                        ], colorKey);
                        return useKeyGen.setSignaturePaddings.call(this, paddings);
                    }

                    useKeyGen.setAlgorithmParameterSpec.implementation = function (spec) {
                        showVariable("KeyGenParameterSpec.setAlgorithmParameterSpec", [
                            { key: "ParameterSpec", value: spec.toString() }
                        ], colorKey);
                        return useKeyGen.setAlgorithmParameterSpec.call(this, spec);
                    }

                    useKeyGen.build.implementation = function () {
                        showVariable("KeyGenParameterSpec.build", [], colorKey);
                        return useKeyGen.build.call(this);
                    }
                }

                if (MODE.IvParameterSpec) {
                    const colorKey = randomColor();
                    console.log("[*] Module attached: javax.crypto.spec.IvParameterSpec");
                    const ivParameter = Java.use("javax.crypto.spec.IvParameterSpec");
                    ivParameter.$init.overload("[B").implementation = function (ivKey) {
                        showVariable("IvParameterSpec.init", [
                            { key: "IV Key", value: bytesToBase64(ivKey) }
                        ], colorKey);
                        return this.$init.overload("[B").call(this, ivKey);
                    }

                    ivParameter.$init.overload("[B", "int", "int").implementation = function (ivKey, offset, len) {
                        showVariable("IvParameterSpec.init", [
                            { key: "IV Key", value: bytesToBase64(ivKey) },
                            { key: "Offset", value: offset },
                            { key: "Length", value: len }
                        ], colorKey);
                        return this.$init.overload("[B", "int", "int").call(this, ivKey, offset, len);
                    }
                }

            });
        } else {
            console.log(`${COLORS.red}[!] Java unavailable${COLORS.reset}`);
        }

        console.log("Capturing setup completed");
        console.log("---");
    }, 0);
}

// Helper function to add color to text
function colorize(text, colorCode) {
    return `\x1b[${colorCode}m${text}\x1b[0m`;
}

// Predefined color codes
const COLORS = {
    red: 31,
    green: 32,
    yellow: 33,
    blue: 34,
    magenta: 35,
    cyan: 36,
    white: 37,
    bold: 1,
    brightBlack: 90,
    brightRed: 91,
    brightGreen: 92,
    brightYellow: 93,
    brightBlue: 94,
    brightMagenta: 95,
    brightCyan: 96,
    brightWhite: 97,
};

var dumpCounter = 1;

function dex_loading_tracer() {

    const JavaFile = Java.use("java.io.File");
    const ActivityThread = Java.use('android.app.ActivityThread');
    const FridaFile = File;

    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");

    // DexClassLoader Constructor:
    try {
        DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log(colorize("[*] DexClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> optimizedDirectory: " + optimizedDirectory, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            // hookDexClassLoaderMethods()
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook DexClassLoader.init: " + e);
    }

    function hookDexClassLoaderMethods() {
        // findclass():
        try {
            DexClassLoader.findClass.overload("java.lang.String").implementation = function (className) {
                console.log(colorize("[+] DexClassLoader -> findClass: " + className, COLORS.magenta));
                // stackTrace()
                return this.findClass(className);
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.findClass: " + e);
        }

        // loadClass():
        try {
            DexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
                console.log(colorize('[*] DexClassLoader.loadClass called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className);
                console.log(colorize('    -> Loaded j.l.Class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.loadClass: " + e);
        }

        // loadClass() overload:
        try {
            DexClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (className, resolve) {
                console.log(colorize('[*] DexClassLoader.loadClass [2] called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className, resolve);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook DexClassLoader.loadClass: " + e);
        }
    }

    const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    //  BaseDexClassLoader Constructor:
    try {
        BaseDexClassLoader.$init.overload("java.lang.String", "java.io.File", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log(colorize("[*] BaseDexClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> optimizedDirectory: " + optimizedDirectory, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            // hookBaseDexClassLoaderMethods()
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook BaseDexClassLoader.init: " + e);
    }

    function hookBaseDexClassLoaderMethods() {
        // findclass():
        try {
            BaseDexClassLoader.findClass.overload("java.lang.String").implementation = function (className) {
                console.log(colorize("[+] BaseDexClassLoader -> findClass: " + className, COLORS.magenta));
                return this.findClass(className);
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.findClass: " + e);
        }

        // loadClass():
        try {
            BaseDexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
                console.log(colorize('[*] BaseDexClassLoader.loadClass called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.loadClass: " + e);
        }

        // loadClass() overload:
        try {
            BaseDexClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (className, resolve) {
                console.log(colorize('[*] BaseDexClassLoader.loadClass [2] called', COLORS.cyan));
                console.log(colorize('    -> Class name: ' + className, COLORS.cyan));
                let loadedClass = this.loadClass(className, resolve);
                console.log(colorize('    -> Loaded class: ' + loadedClass, COLORS.cyan));
                return loadedClass;
            };
        } catch (e) {
            console.log("[-] Could not hook BaseDexClassLoader.loadClass: " + e);
        }
    }

    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    //  PathClassLoader Constructor:
    try {
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, parent) {
            console.log(colorize("[*] PathClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook PathClassLoader.init: " + e);
    }
    //  PathClassLoader Constructor:
    try {
        PathClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, librarySearchPath, parent) {
            console.log(colorize("[*] PathClassLoader($init) called", COLORS.yellow));
            console.log(colorize("    -> dexPath: " + dexPath, COLORS.yellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));
            console.log(colorize("    -> parent: " + parent, COLORS.yellow));
            dumpDexFromPath(dexPath);
            dumpCounter++
            return this.$init(dexPath, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] Could not hook PathClassLoader.init: " + e);
    }

    function dumpDexFromPath(dexPath) {

        const application = ActivityThread.currentApplication();
        if (application === null) {
            console.log(colorize("[-] Cannot dump DEX: application context not yet available.", COLORS.red));
            return;
        }
        const context = application.getApplicationContext();
        const baseDir = context.getFilesDir().getAbsolutePath();
        const dumpDir = JavaFile.$new(`${baseDir}/dump`);

        if (!dumpDir.exists()) {
            dumpDir.mkdirs();
        }

        // Get the original filename from the path to use in the destination
        // const originalFileName = JavaFile.$new(dexPath).getName();
        const destinationPath = `${dumpDir.getAbsolutePath()}/${dumpCounter}`;

        console.log(colorize(`[*] Copying DEX from ${dexPath}`, COLORS.cyan));

        try {
            // --- Read the entire source file into a buffer ---
            const sourceFile = new FridaFile(dexPath, "rb");
            const dexBuffer = sourceFile.readBytes(); // Reads the entire file
            sourceFile.close();

            // --- Write the buffer to the new destination file ---
            const destinationFile = new FridaFile(destinationPath, "wb");
            destinationFile.write(dexBuffer);
            destinationFile.flush();
            destinationFile.close();

            console.log(colorize(`[+] Copied DEX successfully to: ${destinationPath}`, COLORS.brightGreen));
            console.log(colorize(`    -> To retrieve, run: adb pull "${destinationPath}"`, COLORS.white));

        } catch (e) {
            console.log(colorize(`[-] Failed to copy DEX from path: ${e.message}`, COLORS.red));
        }
    }
}



function in_memory_dex_loading_tracer() {
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    const JavaFile = Java.use("java.io.File");
    const ActivityThread = Java.use('android.app.ActivityThread');
    const FridaFile = File; // Alias for Frida's built-in File API

    try {
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buffer, loader) {

            console.log(colorize("[*] InMemoryDexClassLoader($init) called", COLORS.brightYellow));
            console.log(colorize("    -> byteBuffer: " + buffer, COLORS.yellow));
            console.log(colorize("    -> parentClassLoader: " + loader, COLORS.yellow));

            const path = getDirectory().getAbsolutePath();
            dumpDex(buffer, `${path}/${0}`);
            dumpCounter++;
            return this.$init(buffer, loader);
        };
    } catch (e) {
        console.log(colorize("[-] Could not hook InMemoryDexClassLoader.$init: " + e, COLORS.red));
    }

    try {
        InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation = function (buffers, loader) {
            console.log(colorize("\n[*] InMemoryDexClassLoader(ByteBuffer[], ...) hooked!", COLORS.brightYellow));

            const path = getDirectory().getAbsolutePath();
            for (let i = 0; i < buffers.length; i++) {
                dumpDex(buffers[i], `${path}/${i}`);
            }
            dumpCounter++;
            return this.$init(buffers, loader);
        };
    } catch (e) { console.log(colorize("[-] Failed to hook InMemoryDexClassLoader (buffer array): " + e, COLORS.red)); }

    try {
        InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (buffers, librarySearchPath, loader) {
            console.log(colorize("\n[*] InMemoryDexClassLoader(ByteBuffer[], String, ...) hooked!", COLORS.brightYellow));
            console.log(colorize("    -> librarySearchPath: " + librarySearchPath, COLORS.yellow));

            const path = getDirectory().getAbsolutePath();
            for (let i = 0; i < buffers.length; i++) {
                dumpDex(buffers[i], `${path}/${i}`);
            }
            dumpCounter++;
            return this.$init(buffers, librarySearchPath, loader);
        };
    } catch (e) { console.log(colorize("[-] Failed to hook InMemoryDexClassLoader (buffer array with lib path): " + e, COLORS.red)); }

    function getDirectory() {
        const application = ActivityThread.currentApplication();
        if (application === null) {
            console.log(colorize("[-] Cannot dump DEX: application context not yet available.", COLORS.red));
            return;
        }
        const context = application.getApplicationContext();
        const baseDir = context.getFilesDir().getAbsolutePath();
        const dumpDir = JavaFile.$new(`${baseDir}/dump/inmem${dumpCounter}`);

        if (!dumpDir.exists()) {
            dumpDir.mkdirs();
        }
        return dumpDir;
    }

    function dumpDex(byteBuffer, path) {
        byteBuffer.rewind();
        const remaining = byteBuffer.remaining();

        const dexBytes = [];
        for (let i = 0; i < remaining; i++) { dexBytes.push(byteBuffer.get()); }

        const fridaFile = new FridaFile(path, "wb");
        fridaFile.write(dexBytes);
        fridaFile.flush();
        fridaFile.close();

        console.log(colorize(`[+] Dex dumped successfully to ${path}`, COLORS.brightGreen));
        byteBuffer.rewind();
    }
}



function spoofLocale(locale, newLanguageCode, newCountryCode) {
    const Application = Java.use('android.app.Application');
    const Locale = Java.use('java.util.Locale');

    Application.attachBaseContext.implementation = function (context) {
        console.log("Intercepting Application.attachBaseContext to change locale.");

        const resources = context.getResources();
        const config = resources.getConfiguration();
        const newLocale = Locale.forLanguageTag(locale);
        config.setLocale(newLocale);

        const newContext = context.createConfigurationContext(config);
        this.attachBaseContext(newContext);
        console.log("Locale successfully spoofed to: " + newLocale.toString());
    };

    Locale.getCountry.implementation = function () {
        //console.log(`[Locale] Intercepted getCountry(), returning '${newCountryCode}'.`);
        return newCountryCode;
    };

    Locale.getLanguage.implementation = function () {
        //console.log(`[Locale] Intercepted getLanguage(), returning '${newLanguageCode}'.`);
        return newLanguageCode;
    };

    Locale.toLanguageTag.implementation = function () {
        //console.log(`[Locale] Intercepted toLanguageTag(), returning '${newLanguageTag}'.`);
        return locale;
    };
}

/**
 * Applies a comprehensive battery status spoof using direct arguments.
 * @param {number} level - The desired battery level from 0 to 100.
 * @param {boolean} isCharging - true if the device should appear to be charging.
 * @param {number} plugged - The power source type (e.g., 0 for unplugged, 1 for AC, 2 for USB).
 */
function spoofBatteryStatus(level, isCharging, plugged) {
    // Basic validation for the level parameter
    if (level < 0 || level > 100) {
        console.error("[!] Invalid battery level. Please provide a number between 0 and 100.");
        return;
    }

    const Intent = Java.use('android.content.Intent');
    const BatteryManager = Java.use('android.os.BatteryManager');

    // --- Determine Constants from Arguments ---
    const status = isCharging ?
        BatteryManager.BATTERY_STATUS_CHARGING.value :
        BatteryManager.BATTERY_STATUS_DISCHARGING.value;
    
    // Set a sensible default for battery health
    const health = BatteryManager.BATTERY_HEALTH_GOOD.value;

    console.log(`[*] Applying battery hook: level=${level}%, charging=${isCharging}, plugged=${plugged}`);

    // --- Hook 1: Intent Broadcasts ---
    Intent.getIntExtra.overload('java.lang.String', 'int').implementation = function (name, defaultValue) {
        if (name === "level") return level;
        if (name === "scale") return 100;
        if (name === "status") return status;
        if (name === "plugged") return plugged;
        if (name === "health") return health;
        return this.getIntExtra(name, defaultValue);
    };

    // --- Hook 2: Direct BatteryManager Queries ---
    const b_CAPACITY = BatteryManager.BATTERY_PROPERTY_CAPACITY.value;
    const b_STATUS = BatteryManager.BATTERY_PROPERTY_STATUS.value;

    BatteryManager.getIntProperty.implementation = function(propId) {
        if (propId === b_CAPACITY) return level;
        if (propId === b_STATUS) return status;
        return this.getIntProperty(propId);
    };

    console.log("[*] Comprehensive battery status hooks are now active.");
}


function spoofSimInfo(countryIso, operatorName, mcc_mnc, mcc, mnc, imsi, phoneNumber) {
    // Get a wrapper for the Resources class
    const Resources = Java.use('android.content.res.Resources');

    // Hook the getConfiguration() method
    Resources.getConfiguration.implementation = function () {
        // Call the original method to get the real Configuration object
        const config = this.getConfiguration();

        // Modify the mcc and mnc fields directly on the Configuration object
        config.mcc.value = mcc;
        config.mnc.value = mnc;

        // Return the modified object
        return config;
    };
    const TelephonyManager = Java.use('android.telephony.TelephonyManager');

    // --- SIM Card Spoofing ---
    TelephonyManager.getSimCountryIso.overload().implementation = function () { return countryIso; };
    TelephonyManager.getSimCountryIso.overload('int').implementation = function () { return countryIso; };

    TelephonyManager.getSimOperator.overload().implementation = function () { return mcc_mnc; };
    TelephonyManager.getSimOperator.overload('int').implementation = function () { return mcc_mnc; };

    TelephonyManager.getSimOperatorName.overload().implementation = function () { return operatorName; };
    TelephonyManager.getSimOperatorName.overload('int').implementation = function () { return operatorName; };

    // --- Network Spoofing (for consistency) ---
    TelephonyManager.getNetworkCountryIso.overload().implementation = function () { return countryIso; };
    TelephonyManager.getNetworkCountryIso.overload('int').implementation = function () { return countryIso; };

    TelephonyManager.getNetworkOperator.overload().implementation = function () { return mcc_mnc; };
    TelephonyManager.getNetworkOperator.overload('int').implementation = function () { return mcc_mnc; };

    TelephonyManager.getNetworkOperatorName.overload().implementation = function () { return operatorName; };
    TelephonyManager.getNetworkOperatorName.overload('int').implementation = function () { return operatorName; };

    // --- Unique Identifier Spoofing ---
    TelephonyManager.getSubscriberId.overload().implementation = function () {
        console.log(`[SIM] Spoofing IMSI (getSubscriberId) with: ${imsi}`);
        return imsi;
    };
    TelephonyManager.getSubscriberId.overload('int').implementation = function () {
        console.log(`[SIM] Spoofing IMSI (getSubscriberId) with: ${imsi}`);
        return imsi;
    };

    TelephonyManager.getLine1Number.overload().implementation = function () {
        console.log(`[SIM] Spoofing Phone Number (getLine1Number) with: ${phoneNumber}`);
        return phoneNumber;
    };
    TelephonyManager.getLine1Number.overload('int').implementation = function () {
        console.log(`[SIM] Spoofing Phone Number (getLine1Number) with: ${phoneNumber}`);
        return phoneNumber;
    };
}

function spoofTimezone(timezoneId) {
    const TimeZone = Java.use('java.util.TimeZone');
    const String = Java.use('java.lang.String');

    // Hook the static getDefault method to return a spoofed TimeZone object
    TimeZone.getDefault.implementation = function () {
        console.log(`[Timezone] Spoofing TimeZone.getDefault() to '${timezoneId}'.`);
        return TimeZone.getTimeZone(timezoneId);
    };

    // As a fallback, also hook getID() on existing instances
    TimeZone.getID.implementation = function () {
        // We log the original ID before spoofing it
        const originalId = this.getID.call(this);
        console.log(`[Timezone] Intercepted getID() on '${originalId}'. Spoofing to '${timezoneId}'.`);
        return String.$new(timezoneId);
    };
}

function spoofKeyboardLanguage(localeString, languageTag) {
    const InputMethodSubtype = Java.use('android.view.inputmethod.InputMethodSubtype');

    // Hook getLocale() which returns a string like "en_US"
    InputMethodSubtype.getLocale.implementation = function() {
        const originalLocale = this.getLocale();
        console.log(`[Keyboard] Intercepted getLocale(). Original: ${originalLocale}, Spoofing to: ${localeString}`);
        return localeString;
    };

    // Hook getLanguageTag() which returns a BCP 47 tag like "en-US"
    InputMethodSubtype.getLanguageTag.implementation = function() {
        const originalTag = this.getLanguageTag();
        console.log(`[Keyboard] Intercepted getLanguageTag(). Original: ${originalTag}, Spoofing to: ${languageTag}`);
        return languageTag;
    };
}


function hookLocation(mockLocationData) {
    const TAG = "[LocationApiHooks]";

    const MockPreferences = {
        getUseAccuracy: function () { return true; },
        getUseAltitude: function () { return true; },
        getUseVerticalAccuracy: function () { return true; },
        getUseSpeed: function () { return true; },
        getUseSpeedAccuracy: function () { return true; },
        getUseMeanSeaLevel: function () { return true; },
        getUseMeanSeaLevelAccuracy: function () { return true; }
    };


    try {
        const Location = Java.use("android.location.Location");

        // Define the methods to hook on the Location class
        const methodsToHook = [
            "getLatitude",
            "getLongitude",
            "getAccuracy",
            "getAltitude",
            "getVerticalAccuracyMeters",
            "getSpeed",
            "getSpeedAccuracyMetersPerSecond"
        ];

        // Conditionally add API-level specific methods
        if (Java.androidVersion >= 31) {
            methodsToHook.push("getMslAltitudeMeters", "getMslAltitudeAccuracyMeters");
        } else {
            console.log(TAG + " getMslAltitudeMeters() and getMslAltitudeAccuracyMeters() not available on this API level");
        }

        methodsToHook.forEach(function (methodName) {
            const method = Location[methodName].overload();
            method.implementation = function () {
                const originalResult = method.call(this);
                console.log(TAG + " Leaving method " + methodName + "()");
                console.log("\t Original result: " + originalResult);

                let modifiedResult = originalResult;

                switch (methodName) {
                    case "getLatitude":
                        modifiedResult = mockLocationData.latitude;
                        break;
                    case "getLongitude":
                        modifiedResult = mockLocationData.longitude;
                        break;
                    case "getAccuracy":
                        if (MockPreferences.getUseAccuracy()) {
                            modifiedResult = mockLocationData.accuracy;
                        }
                        break;
                    case "getAltitude":
                        if (MockPreferences.getUseAltitude()) {
                            modifiedResult = mockLocationData.altitude;
                        }
                        break;
                    case "getVerticalAccuracyMeters":
                        if (MockPreferences.getUseVerticalAccuracy()) {
                            modifiedResult = mockLocationData.verticalAccuracy;
                        }
                        break;
                    case "getSpeed":
                        if (MockPreferences.getUseSpeed()) {
                            modifiedResult = mockLocationData.speed;
                        }
                        break;
                    case "getSpeedAccuracyMetersPerSecond":
                        if (MockPreferences.getUseSpeedAccuracy()) {
                            modifiedResult = mockLocationData.speedAccuracy;
                        }
                        break;
                    case "getMslAltitudeMeters":
                        if (MockPreferences.getUseMeanSeaLevel()) {
                            modifiedResult = mockLocationData.meanSeaLevel;
                        }
                        break;
                    case "getMslAltitudeAccuracyMeters":
                        if (MockPreferences.getUseMeanSeaLevelAccuracy()) {
                            modifiedResult = mockLocationData.meanSeaLevelAccuracy;
                        }
                        break;
                }

                console.log("\t Modified to: " + modifiedResult);
                return modifiedResult;
            };
        });
    } catch (e) {
        console.log(TAG + " Error hooking Location class - " + e.message);
    }
}

function hookLocationManager(mockLocationData) {
    const TAG = "[LocationApiHooks]";
    try {
        const LocationManager = Java.use("android.location.LocationManager");
        const Location = Java.use("android.location.Location");

        LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
            console.log(TAG + " Leaving method getLastKnownLocation(provider)");
            const originalLocation = this.getLastKnownLocation(provider);
            console.log("\t Original location: " + originalLocation);
            console.log("\t Requested data from: " + provider);

            const fakeLocation = Location.$new(provider);
            fakeLocation.setLatitude(mockLocationData.latitude);
            fakeLocation.setLongitude(mockLocationData.longitude);
            // Additional properties could be set here based on the original Kotlin code.

            console.log("\t Modified location: " + fakeLocation);
            return fakeLocation;
        };
    } catch (e) {
        console.log(TAG + " Error hooking LocationManager - " + e.message);
    }
}

function spoofDeviceCountry(countryCode) {
    const countryProfiles = {
        // Brazil
        "BR": {
            locale: 'pt-BR', country: 'BR', langCode: 'pt', timezone: 'America/Sao_Paulo', displayLang: 'Portuguese',
            mcc_mnc: '72402', mcc: 724, mnc: 2, operatorName: 'TIM',
            mockLocationData: {
                latitude: -23.5500, longitude: -46.6333, city: 'São Paulo',
                accuracy: 10.0, altitude: 760.0, verticalAccuracy: 5.0, speed: 15.0, speedAccuracy: 3.0,
                meanSeaLevel: 750.0, meanSeaLevelAccuracy: 4.0
            }
        },
        // United States
        "US": {
            locale: 'en-US', country: 'US', langCode: 'en', timezone: 'America/New_York', displayLang: 'English',
            mcc_mnc: '310410', mcc: 310, mnc: 410, operatorName: 'AT&T',
            mockLocationData: {
                latitude: 38.9072, longitude: -77.0369, city: 'Washington, D.C.',
                accuracy: 5.0, altitude: 100.0, verticalAccuracy: 2.5, speed: 10.0, speedAccuracy: 1.5,
                meanSeaLevel: 95.0, meanSeaLevelAccuracy: 2.0
            }
        },
        // India
        "IN": {
            locale: 'hi-IN', country: 'IN', langCode: 'hi', timezone: 'Asia/Kolkata', displayLang: 'Hindi',
            mcc_mnc: '40431', mcc: 404, mnc: 31, operatorName: 'Jio',
            mockLocationData: {
                latitude: 28.7041, longitude: 77.1025, city: 'Delhi',
                accuracy: 12.0, altitude: 216.0, verticalAccuracy: 6.0, speed: 8.0, speedAccuracy: 2.5,
                meanSeaLevel: 210.0, meanSeaLevelAccuracy: 5.0
            }
        },
        // Turkey
        "TR": {
            locale: 'tr-TR', country: 'TR', langCode: 'tr', timezone: 'Europe/Istanbul', displayLang: 'Turkish',
            mcc_mnc: '28601', mcc: 286, mnc: 1, operatorName: 'Turkcell',
            mockLocationData: {
                latitude: 41.0082, longitude: 28.9784, city: 'Istanbul',
                accuracy: 8.0, altitude: 40.0, verticalAccuracy: 4.0, speed: 20.0, speedAccuracy: 4.0,
                meanSeaLevel: 30.0, meanSeaLevelAccuracy: 3.5
            }
        },
        // Ukraine
        "UA": {
            locale: 'uk-UA', country: 'UA', langCode: 'uk', timezone: 'Europe/Kiev', displayLang: 'Ukrainian',
            mcc_mnc: '25501', mcc: 255, mnc: 1, operatorName: 'Kyivstar',
            mockLocationData: {
                latitude: 50.4501, longitude: 30.5234, city: 'Kyiv',
                accuracy: 7.0, altitude: 179.0, verticalAccuracy: 3.5, speed: 12.0, speedAccuracy: 2.0,
                meanSeaLevel: 175.0, meanSeaLevelAccuracy: 3.0
            }
        },
        // Indonesia
        "ID": {
            locale: 'id-ID', country: 'ID', langCode: 'id', timezone: 'Asia/Jakarta', displayLang: 'Indonesian',
            mcc_mnc: '51010', mcc: 510, mnc: 10, operatorName: 'Telkomsel',
            mockLocationData: {
                latitude: -6.2088, longitude: 106.8456, city: 'Jakarta',
                accuracy: 9.0, altitude: 7.0, verticalAccuracy: 2.0, speed: 5.0, speedAccuracy: 1.0,
                meanSeaLevel: 5.0, meanSeaLevelAccuracy: 1.5
            }
        },
        // Thailand
        "TH": {
            locale: 'th-TH', country: 'TH', langCode: 'th', timezone: 'Asia/Bangkok', displayLang: 'Thai',
            mcc_mnc: '52003', mcc: 520, mnc: 3, operatorName: 'AIS',
            mockLocationData: {
                latitude: 13.7563, longitude: 100.5018, city: 'Bangkok',
                accuracy: 6.0, altitude: 1.5, verticalAccuracy: 1.0, speed: 10.0, speedAccuracy: 2.0,
                meanSeaLevel: 0.5, meanSeaLevelAccuracy: 0.8
            }
        },
        // United Arab Emirates
        "AE": {
            locale: 'ar-AE', country: 'AE', langCode: 'ar', timezone: 'Asia/Dubai', displayLang: 'Arabic',
            mcc_mnc: '42402', mcc: 424, mnc: 2, operatorName: 'Etisalat',
            mockLocationData: {
                latitude: 25.276987, longitude: 55.296249, city: 'Dubai',
                accuracy: 4.0, altitude: 5.0, verticalAccuracy: 1.5, speed: 25.0, speedAccuracy: 5.0,
                meanSeaLevel: 2.0, meanSeaLevelAccuracy: 2.5
            }
        },
        // United Kingdom
        "GB": {
            locale: 'en-GB', country: 'GB', langCode: 'en', timezone: 'Europe/London', displayLang: 'English',
            mcc_mnc: '23410', mcc: 234, mnc: 10, operatorName: 'O2',
            mockLocationData: {
                latitude: 51.5072, longitude: -0.1275, city: 'London',
                accuracy: 3.0, altitude: 35.0, verticalAccuracy: 1.2, speed: 8.0, speedAccuracy: 1.0,
                meanSeaLevel: 30.0, meanSeaLevelAccuracy: 1.0
            }
        },
        // Saudi Arabia
        "SA": {
            locale: 'ar-SA', country: 'SA', langCode: 'ar', timezone: 'Asia/Riyadh', displayLang: 'Arabic',
            mcc_mnc: '42001', mcc: 420, mnc: 1, operatorName: 'STC',
            mockLocationData: {
                latitude: 24.7136, longitude: 46.6753, city: 'Riyadh',
                accuracy: 9.0, altitude: 600.0, verticalAccuracy: 4.5, speed: 22.0, speedAccuracy: 3.5,
                meanSeaLevel: 590.0, meanSeaLevelAccuracy: 4.0
            }
        },
        // Austria
        "AT": {
            locale: 'de-AT', country: 'AT', langCode: 'de', timezone: 'Europe/Vienna', displayLang: 'German',
            mcc_mnc: '23201', mcc: 232, mnc: 1, operatorName: 'A1',
            mockLocationData: {
                latitude: 48.2083, longitude: 16.3725, city: 'Vienna',
                accuracy: 6.0, altitude: 180.0, verticalAccuracy: 3.0, speed: 18.0, speedAccuracy: 2.8,
                meanSeaLevel: 175.0, meanSeaLevelAccuracy: 2.5
            }
        },
        // Malaysia
        "MY": {
            locale: 'ms-MY', country: 'MY', langCode: 'ms', timezone: 'Asia/Kuala_Lumpur', displayLang: 'Malay',
            mcc_mnc: '50219', mcc: 502, mnc: 19, operatorName: 'Celcom',
            mockLocationData: {
                latitude: 3.1390, longitude: 101.6869, city: 'Kuala Lumpur',
                accuracy: 8.0, altitude: 80.0, verticalAccuracy: 3.8, speed: 12.0, speedAccuracy: 2.2,
                meanSeaLevel: 75.0, meanSeaLevelAccuracy: 3.0
            }
        },
        // Pakistan
        "PK": {
            locale: 'ur-PK', country: 'PK', langCode: 'ur', timezone: 'Asia/Karachi', displayLang: 'Urdu',
            mcc_mnc: '41001', mcc: 410, mnc: 1, operatorName: 'Jazz',
            mockLocationData: {
                latitude: 24.8600, longitude: 67.0100, city: 'Karachi',
                accuracy: 15.0, altitude: 8.0, verticalAccuracy: 4.2, speed: 7.0, speedAccuracy: 1.8,
                meanSeaLevel: 5.0, meanSeaLevelAccuracy: 2.0
            }
        },
        // Kazakhstan
        "KZ": {
            locale: 'kk-KZ', country: 'KZ', langCode: 'kk', timezone: 'Asia/Almaty', displayLang: 'Kazakh',
            mcc_mnc: '40101', mcc: 401, mnc: 1, operatorName: 'Beeline',
            mockLocationData: {
                latitude: 43.2389, longitude: 76.8897, city: 'Almaty',
                accuracy: 11.0, altitude: 780.0, verticalAccuracy: 5.5, speed: 18.0, speedAccuracy: 3.0,
                meanSeaLevel: 770.0, meanSeaLevelAccuracy: 4.5
            }
        },
        // Iran
        "IR": {
            locale: 'fa-IR', country: 'IR', langCode: 'fa', timezone: 'Asia/Tehran', displayLang: 'Persian',
            mcc_mnc: '43211', mcc: 432, mnc: 11, operatorName: 'MCI',
            mockLocationData: {
                latitude: 35.6892, longitude: 51.3890, city: 'Tehran',
                accuracy: 13.0, altitude: 1200.0, verticalAccuracy: 6.5, speed: 14.0, speedAccuracy: 2.5,
                meanSeaLevel: 1190.0, meanSeaLevelAccuracy: 5.0
            }
        },
        // Russia
        "RU": {
            locale: 'ru-RU', country: 'RU', langCode: 'ru', timezone: 'Europe/Moscow', displayLang: 'Russian',
            mcc_mnc: '25001', mcc: 250, mnc: 1, operatorName: 'MTS',
            mockLocationData: {
                latitude: 55.7558, longitude: 37.6172, city: 'Moscow',
                accuracy: 7.0, altitude: 156.0, verticalAccuracy: 3.2, speed: 20.0, speedAccuracy: 3.0,
                meanSeaLevel: 150.0, meanSeaLevelAccuracy: 2.8
            }
        },
        // Japan
        "JP": {
            locale: 'ja-JP', country: 'JP', langCode: 'ja', timezone: 'Asia/Tokyo', displayLang: 'Japanese',
            mcc_mnc: '44010', mcc: 440, mnc: 10, operatorName: 'Docomo',
            mockLocationData: {
                latitude: 35.6895, longitude: 139.6917, city: 'Tokyo',
                accuracy: 5.0, altitude: 40.0, verticalAccuracy: 2.0, speed: 18.0, speedAccuracy: 2.5,
                meanSeaLevel: 35.0, meanSeaLevelAccuracy: 1.8
            }
        },
        // China
        "CN": {
            locale: 'zh-CN', country: 'CN', langCode: 'zh', timezone: 'Asia/Shanghai', displayLang: 'Chinese',
            mcc_mnc: '46000', mcc: 460, mnc: 0, operatorName: 'China Mobile',
            mockLocationData: {
                latitude: 31.2304, longitude: 121.4737, city: 'Shanghai',
                accuracy: 8.0, altitude: 4.0, verticalAccuracy: 1.5, speed: 15.0, speedAccuracy: 2.0,
                meanSeaLevel: 2.0, meanSeaLevelAccuracy: 1.2
            }
        }
    };

    const profile = countryProfiles[countryCode];

    if (!profile) {
        console.error(`[!] No profile found for country code: ${countryCode}`);
        console.log(`[*] Available profiles: ${Object.keys(countryProfiles).join(', ')}`);
        return;
    }

    console.log(`[*] Applying spoofing profile for ${profile.operatorName}, ${profile.country}...`);

    // Call the individual hook functions with the profile data
    spoofLocale(profile.locale, profile.langCode, profile.country);
    spoofSimInfo(profile.country, profile.operatorName, profile.mcc_mnc, profile.mcc, profile.mnc, profile.imsi, profile.phoneNumber);
    spoofTimezone(profile.timezone);
    spoofKeyboardLanguage(profile.locale.replace('-', '_'), profile.locale)
    hookLocation(profile.mockLocationData);
    hookLocationManager(profile.mockLocationData);
}


Java.perform(() => {
    console.log("🚀 Activating hooks...");
    setupSystemPropertyHooks();
    VPNHook();
    bypassNetworkConnectionChecks(true);
    ssl_unpinning_multiple();
    bypassRootChecks();

    spoofBatteryStatus(50, false, 0);

    spoofDeviceCountry("BR");

    // spoofSimInfo("BR", "72410", "Vivo");
    // spoofTimezone("America/Sao_Paulo");

    installReferrerHook("facebook", "social");
    // installReferrerHook("google-play", "non-organic");
    pairipHook();

    dex_loading_tracer()
    in_memory_dex_loading_tracer();
    // android_crypto_intercept();

    //   print_logs();
    console.log("✅ Hooks are active. Monitoring for requests.");

});
