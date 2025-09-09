send("Script start loading");

function multipleUnpining() {
    setTimeout(function () {
        send("MultipleUnpinning start loading");
        Java.perform(function () {
            send("in Java perform Loading MultipleUnpinning");
            console.log('');
            console.log('======');
            console.log('[#] Android Bypass for various Certificate Pinning methods [#]');
            console.log('======');


            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            // TrustManager (Android < 7) //
            ////////////////////////////////
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
            }
            try {
                // Bypass Trustkit {3}
                var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
                trustkit_PinningTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (chain, authType) {
                    console.log('[+] Bypassing Trustkit {3}');
                    //return;
                };
            } catch (err) {
                console.log('[-] Trustkit {3} pinner not found');
                //console.log(err);
            }




            // TrustManagerImpl (Android > 7) //
            ////////////////////////////////////
            try {
                // Bypass TrustManagerImpl (Android > 7) {1}
                var array_list = Java.use("java.util.ArrayList");
                var TrustManagerImpl_Activity_1 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ' + host);
                    return array_list.$new();
                };
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found');
                //console.log(err);
            }
            try {
                // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
                var TrustManagerImpl_Activity_2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl_Activity_2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    console.log('[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check: ' + host);
                    return untrustedChain;
                };
            } catch (err) {
                console.log('[-] TrustManagerImpl (Android > 7) verifyChain check not found');
                //console.log(err);
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
            }
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certChain, authMethod) {
                    console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt {2}');
                };
            } catch (err) {
                console.log('[-] OpenSSLSocketImpl Conscrypt {2} pinner not found');
                //console.log(err);        
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
            }




            // Conscrypt CertPinManager //
            //////////////////////////////
            try {
                var conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
                conscrypt_CertPinManager_Activity.checkChainPinning.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
                    console.log('[+] Bypassing Conscrypt CertPinManager: ' + a);
                    //return;
                    return true;
                };
            } catch (err) {
                console.log('[-] Conscrypt CertPinManager pinner not found');
                //console.log(err);
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
            }
            try {
                // Bypass WebViewClient {2}
                var AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
                    console.log('[+] Bypassing Android WebViewClient check {2}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {2} check not found');
                //console.log(err)
            }
            try {
                // Bypass WebViewClient {3}
                var AndroidWebViewClient_Activity_3 = Java.use('android.webkit.WebViewClient');
                AndroidWebViewClient_Activity_3.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (obj1, obj2, obj3, obj4) {
                    console.log('[+] Bypassing Android WebViewClient check {3}');
                };
            } catch (err) {
                console.log('[-] Android WebViewClient {3} check not found');
                //console.log(err)
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
                    console.log('[+] Bypassing Boye AbstractVerifier check: ' + host);
                };
            } catch (err) {
                console.log('[-] Boye AbstractVerifier check not found');
                //console.log(err);
            }




            // Apache AbstractVerifier //
            /////////////////////////////
            try {
                var apache_AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
                apache_AbstractVerifier.verify.implementation = function (a, b, c, d) {
                    console.log('[+] Bypassing Apache AbstractVerifier check: ' + a);
                    return;
                };
            } catch (err) {
                console.log('[-] Apache AbstractVerifier check not found');
                //console.log(err);
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
            }




            // Dynamic SSLPeerUnverifiedException Patcher                                //
            // An useful technique to bypass SSLPeerUnverifiedException failures raising //
            // when the Android app uses some uncommon SSL Pinning methods or an heavily //
            // code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
            ///////////////////////////////////////////////////////////////////////////////
            function rudimentaryFix(typeName) {
                // This is a improvable rudimentary fix, if not works you can patch it manually
                if (typeName === undefined) {
                    return;
                } else if (typeName === 'boolean') {
                    return true;
                } else {
                    return null;
                }
            }
            try {
                var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
                UnverifiedCertError.$init.implementation = function (str) {
                    console.log('\x1b[36m[!] Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...\x1b[0m');
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
                        console.log('\x1b[36m[!] Attempting to bypass uncommon SSL Pinning method on: ' + className + '.' + methodName + '\x1b[0m');
                        // Skip it when already patched by Frida
                        if (callingMethod.implementation) {
                            return;
                        }
                        // Trying to patch the uncommon SSL Pinning method via implementation
                        var returnTypeName = callingMethod.returnType.type;
                        callingMethod.implementation = function () {
                            rudimentaryFix(returnTypeName);
                        };
                    } catch (e) {
                        // Dynamic patching via implementation does not works, then trying via function overloading
                        //console.log('[!] The uncommon SSL Pinning method has more than one overload); 
                        if (String(e).includes(".overload")) {
                            var splittedList = String(e).split(".overload");
                            for (let i = 2; i < splittedList.length; i++) {
                                var extractedOverload = splittedList[i].trim().split("(")[1].slice(0, -1).replaceAll("'", "");
                                // Check if extractedOverload has multiple arguments
                                if (extractedOverload.includes(",")) {
                                    // Go here if overloaded method has multiple arguments (NOTE: max 6 args are covered here)
                                    var argList = extractedOverload.split(", ");
                                    console.log('\x1b[36m[!] Attempting overload of ' + className + '.' + methodName + ' with arguments: ' + extractedOverload + '\x1b[0m');
                                    if (argList.length == 2) {
                                        callingMethod.overload(argList[0], argList[1]).implementation = function (a, b) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 3) {
                                        callingMethod.overload(argList[0], argList[1], argList[2]).implementation = function (a, b, c) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 4) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3]).implementation = function (a, b, c, d) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 5) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4]).implementation = function (a, b, c, d, e) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    } else if (argNum == 6) {
                                        callingMethod.overload(argList[0], argList[1], argList[2], argList[3], argList[4], argList[5]).implementation = function (a, b, c, d, e, f) {
                                            rudimentaryFix(returnTypeName);
                                        }
                                    }
                                    // Go here if overloaded method has a single argument
                                } else {
                                    callingMethod.overload(extractedOverload).implementation = function (a) {
                                        rudimentaryFix(returnTypeName);
                                    }
                                }
                            }
                        } else {
                            console.log('\x1b[36m[-] Failed to dynamically patch SSLPeerUnverifiedException ' + e + '\x1b[0m');
                        }
                    }
                    //console.log('\x1b[36m[+] SSLPeerUnverifiedException hooked\x1b[0m');
                    return this.$init(str);
                };
            } catch (err) {
                //console.log('\x1b[36m[-] SSLPeerUnverifiedException not found\x1b[0m');
                //console.log('\x1b[36m'+err+'\x1b[0m');
            }

        });
        send("Multiple Unpinning Loaded");

    }, 0);
}

// Trace all Start
var Color = {
    RESET: "\x1b[39;49;00m",
    Black: "0;01",
    Blue: "4;01",
    Cyan: "6;01",
    Gray: "7;11",
    Green: "2;01",
    Purple: "5;01",
    Red: "1;01",
    Yellow: "3;01",
    Light: {
        Black: "0;11",
        Blue: "4;11",
        Cyan: "6;11",
        Gray: "7;01",
        Green: "2;11",
        Purple: "5;11",
        Red: "1;11",
        Yellow: "3;11"
    }
};

/**
 *
 * @param input. 
 *      If an object is passed it will print as json 
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log',
        colorPrefix = '\x1b[3',
        colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

var printBacktrace = function () {
    Java.perform(function () {
        var android_util_Log = Java.use('android.util.Log'),
            java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function traceClass(targetClass) {
    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
        parsedMethods.push(methodReplace);
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod);
    });
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    send({ tracing: targetClassMethod, overloaded: overloadCount });

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString() : 'null' });
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { val: retval, str: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            send(log);
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}
// Trace all End

function anti_root() {
    Java.perform(function () {
        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
        ];

        var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use('java.lang.Runtime');

        var NativeFile = Java.use('java.io.File');

        var String = Java.use('java.lang.String');

        var SystemProperties = Java.use('android.os.SystemProperties');

        var BufferedReader = Java.use('java.io.BufferedReader');

        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        var StringBuffer = Java.use('java.lang.StringBuffer');

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

        if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
        };

        NativeFile.exists.implementation = function () {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload('[Ljava.lang.String;');
        var exec1 = Runtime.exec.overload('java.lang.String');
        var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
        var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
        var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
        var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

        exec5.implementation = function (cmd, env, dir) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function (cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function (cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function (cmd, env) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function (cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec.call(this, fakeCmd);
                }
                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (cmd.indexOf("which su") != -1) {
                    let fakeCmd = 'pwd | grep zzzzz';
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec.call(this, cmd);
        };

        exec1.implementation = function (cmd) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd.indexOf("which su") != -1) {
                let fakeCmd = 'pwd | grep zzzzz';
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function (name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload('java.lang.String');

        get.implementation = function (name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function (args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function (retval) {

            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function (args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function (retval) {

            }
        });

        /*
    
        TO IMPLEMENT:
    
        Exec Family
    
        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);
    
        */


        BufferedReader.readLine.overload('boolean').implementation = function () {
            var text = this.readLine.overload('boolean').call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload('java.util.List');

        ProcessBuilder.start.implementation = function () {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
            var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

            ProcManExec.implementation = function (cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function (cmd, env, directory, stdin, stdout, stderr, redirect) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function () {
                send("Bypass isInsideSecureHardware");
                return true;
            }
        }

    });

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
                console.log("Anti Root Detect - check file: " + filename)
                return false;
            }

            if (commonPaths.indexOf(filename) >= 0) {
                console.log("Anti Root Detect - check file: " + filename)
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
                        console.log("Anti Root Detect - fopen : " + this.inputPath)
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
                        console.log("Anti Root Detect - access : " + this.inputPath)
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
                console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }

            if (cmdarray[0] == "getprop") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString())
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
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString())
                    arguments[0] = Java.array('java.lang.String', [String.$new("")])
                    return ProcessImpl.start.apply(this, arguments)
                }
            }

            return ProcessImpl.start.apply(this, arguments)
        }
    }


    console.log("Attach");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();
}

function hook_reflection() {
    Java.perform(function () {

        var internalClasses = []; // uncomment this if you want no filtering!

        // var internalClasses = ["android.", "com.android", "java.lang", "java.io"]; // comment this for no filtering

        var classDef = Java.use('java.lang.Class');

        var classLoaderDef = Java.use('java.lang.ClassLoader');

        var forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');

        var loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');

        var getMethod = classDef.getMethod.overload('java.lang.String', '[Ljava.lang.Class;');

        // var newInstance = classDef.newInstance.overload();

        // newInstance.implementation = function () {
        //     send('[*] newInstance: ' + this.getName());
        //     var ret = newInstance.call(this);
        //     return ret;
        // };

        getMethod.implementation = function (param1, param2) {
            send('[*] Get Method : [' + param1 + ']');
            stackTrace();
            var ret = getMethod.call(this, param1, param2);
            return ret;
        };

        forName.implementation = function (class_name, flag, class_loader) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                send("Reflection => forName => " + class_name);
                stackTrace();
            }
            return forName.call(this, class_name, flag, class_loader);
        }

        loadClass.implementation = function (class_name, resolve) {
            var isGood = true;
            for (var i = 0; i < internalClasses.length; i++) {
                if (class_name.startsWith(internalClasses[i])) {
                    isGood = false;
                }
            }
            if (isGood) {
                send("Reflection => loadClass => " + class_name);
                stackTrace();
            }
            return loadClass.call(this, class_name, resolve);
        }
    });
}

function hook_dexclassloader() {
    Java.perform(function () {
        //Create a Wapper of DexClassLoader
        var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
        //hook its constructor $init, we will print out its four parameters.
        dexclassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            send("dexPath:" + dexPath);
            send("optimizedDirectory:" + optimizedDirectory);
            send("librarySearchPath:" + librarySearchPath);
            send("parent:" + parent);
            //Without breaking its original logic, we call its original constructor.
            this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        }
    });
}

function hook_InMemoryDexClassLoader() {
    Java.perform(function () {
        var IMdexclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        IMdexclassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (byteBuffer, classLoader) {
            send("InMemoryDexClassLoader constructor");
            send("byteBuffer:" + byteBuffer);
            send("classLoader:" + classLoader);
            this.$init(byteBuffer, classLoader);
        }
    });
}

function hook_DexFile_loadClass() {
    Java.perform(function () {
        var dexFileCls = Java.use('dalvik.system.DexFile');

        dexFileCls.loadClass.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (name, loader) {
            send("Hooked DexFile loadClass, Class name: " + name);
            stackTrace();
            return this.loadClass(name, loader);
        }

        dexFileCls.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (srcPath, outPath, flags) {
            send("Hooked DexFile loadDex, srcPath: " + srcPath + ", outPath: " + outPath + ", flags" + flags);
            stackTrace();
            return this.loadDex(srcPath, outPath, flags);
        }
    });
}


function ok_http_ssl_cert_bypass() {
    setTimeout(function () {

        Java.perform(function () {

            var okhttp3_CertificatePinner_class = null;
            try {
                okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');
            } catch (err) {
                send('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
                okhttp3_CertificatePinner_class = null;
            }

            if (okhttp3_CertificatePinner_class != null) {

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str, list) {
                        send('[+] Bypassing OkHTTPv3 1: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 1');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 1');
                }

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str, cert) {
                        send('[+] Bypassing OkHTTPv3 2: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 2');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 2');
                }

                try {
                    okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str, cert_array) {
                        send('[+] Bypassing OkHTTPv3 3: ' + str);
                        return true;
                    };
                    send('[+] Loaded OkHTTPv3 hook 3');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 3');
                }

                try {
                    okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str, obj) {
                        send('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
                    };
                    send('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
                } catch (err) {
                    send('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
                }

            }

        });

    }, 0);
}


var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    base64DecodeChars = new Array((-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), 62, (-1), (-1), (-1), 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, (-1), (-1), (-1), (-1), (-1), (-1), (-1), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, (-1), (-1), (-1), (-1), (-1), (-1), 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, (-1), (-1), (-1), (-1), (-1));

function bytesToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e[a++],
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}

function hook_encryption_aes() {
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
        var result = this.$init(a, b);
        send("================= SecretKeySpec =====================");
        send("SecretKeySpec :: bytesToString :: " + bytesToString(a));
        send("SecretKeySpec :: bytesToBase64 :: " + bytesToBase64(a));
        send("SecretKeySpec :: bytesToHex :: " + bytesToHex(a));
        return result;
    }


    var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    ivParameterSpec.$init.overload('[B').implementation = function (a) {
        var result = this.$init(a);
        send("\n================== IvParameterSpec ====================");
        send("IvParameterSpec :: bytesToString :: " + bytesToString(a));
        send("IvParameterSpec :: bytesToBase64 :: " + bytesToBase64(a));
        send("IvParameterSpec :: bytesToHex :: " + bytesToHex(a));
        return result;
    }
}

function hook_encryption_cipher() {
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
        var result = this.init(a, b, c);
        send("\n================ cipher.init() ======================");

        if (a == '1') {
            send("init :: Encrypt Mode");
        } else if (a == '2') {
            send("init :: Decrypt Mode");
        }

        send("Mode :: " + a);
        return result;
    }
}

function hook_encryption_doFinal() {
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.doFinal.overload("[B").implementation = function (x) {
        send("\n================ doFinal() ======================");
        var ret = cipher.doFinal.overload("[B").call(this, x);
        send("doFinal :: data to encrypt/decrypt - base64 :: " + bytesToBase64(x));
        send("doFinal :: data to encrypt/decrypt - string :: " + bytesToString(x));
        send("doFinal :: data to encrypt/decrypt - return value :: " + ret);
        send("doFinal :: data to encrypt/decrypt - return value :: " + String.fromCharCode.apply(String, ret));
        stackTrace();
        return ret;
    }
}

function bytesToString(arr) {
    var str = '';
    arr = new Uint8Array(arr);
    for (var i in arr) {
        str += String.fromCharCode(arr[i]);
    }
    return str;
}

function bytesToHex(arr) {
    var str = '';
    var k, j;
    for (var i = 0; i < arr.length; i++) {
        k = arr[i];
        j = k;
        if (k < 0) {
            j = k + 256;
        }
        if (j < 16) {
            str += "0";
        }
        str += j.toString(16);
    }
    return str;
}

function printHashMap(map) {
    Java.perform(function () {
        var HashMapNode = Java.use('java.util.HashMap$Node');
        var iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = Java.cast(iterator.next(), HashMapNode);
            send("Key: " + entry.getKey() + ", Value: " + entry.getValue());
        }
    });
}

function UpdateHashMap(map, mapKey, newVal) {
    Java.perform(function () {
        var HashMapNode = Java.use('java.util.HashMap$Node');
        var iterator = map.entrySet().iterator();
        var jvar;
        if (typeof (newVal) == 'boolean') {
            jvar = Java.use('java.lang.Boolean').$new(newVal);
        }
        if (typeof (newVal) == 'string') {
            jvar = Java.use('java.lang.String').$new(newVal);
        }
        if (typeof (newVal) == 'number') {
            jvar = Java.use('java.lang.Integer').$new(newVal);
        }
        if (jvar != null) {
            var objVal = Java.cast(jvar, Java.use('java.lang.Object'));
            while (iterator.hasNext()) {
                var entry = Java.cast(iterator.next(), HashMapNode);
                var keyStr = entry.getKey().toString();
                if (keyStr.indexOf(mapKey) == 0) {
                    send("found key " + mapKey + " ,replacing value " + entry.getValue() + " with " + newVal);
                    entry.setValue(objVal);
                    send("updated value " + entry.getValue());
                }
            }
        }

    });
}

function printByteArr(bArr) {
    Java.perform(function () {
        var buffer = Java.array('byte', bArr);
        var result = "";
        for (var i = 0; i < buffer.length; ++i) {
            try {
                result += (String.fromCharCode(buffer[i]));
            } catch {
                send("failed adding bytes to string");
            }
        }
        send("Byte arr: \n" + result);
    });
}

function stackTrace() {
    var ThreadDef = Java.use('java.lang.Thread');
    var ThreadObj = ThreadDef.$new();
    var stack = ThreadObj.currentThread().getStackTrace();
    for (var i = 0; i < stack.length; i++) {
        send(i + " => " + stack[i].toString());
    }
}

function stackTrace2() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
}

function stringFromArray(data) {
    var count = data.length;
    var str = "";

    for (var index = 0; index < count; index += 1)
        str += String.fromCharCode(data[index]);

    return str;
}

function hook_webview_loadUrl(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('android.webkit.WebView').loadUrl.overload('java.lang.String').implementation = function (str) {
            send("## Hooked loadUrl, str: " + str);
            // this.setWebContentsDebuggingEnabled(true);
            // send("[+]Setting the value of setWebContentsDebuggingEnabled() to TRUE");
            if (str != null && str.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.loadUrl(str);
        }
    });
}

function hook_webview_loadUrl_2(stackTraceIfContains) {
    Java.perform(function () {
        var WebView = Java.use('android.webkit.WebView');
        // Hook the overload that takes a String and a Map<String, String>
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
            send("## Hooked loadUrl2,  url: " + url + ", Headers: " + printHashMap(headers));
            if (url != null && url.indexOf(stackTraceIfContains) !== -1) {
                // If you have a stackTrace function implemented, call it here
                stackTrace();
            }
            // Proceed with the original call
            return this.loadUrl(url, headers);
        };
    });
}

function hook_URL_openConnection(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('java.net.URL').openConnection.overload().implementation = function () {
            var url = this.toString();
            send("Hooked URL openConnection ,url: " + url);
            if (url.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.openConnection();
        }
    });
}

function hook_URL_new(stackTraceIfContains) {
    Java.perform(function () {
        Java.use('java.net.URL').$init.overload('java.lang.String').implementation = function (str) {
            send("Hooked URL_new ,url: " + str);
            if (str.indexOf(stackTraceIfContains) != -1) {
                stackTrace();
            }
            return this.$init(str);
        }
    });
}

function hook_fileDelete() {
    Java.perform(function () {
        Java.use('java.io.File').delete.overload().implementation = function () {
            var path = this.toString();
            send("Hooked File delete ,File: " + path);
            if (path.indexOf('') != -1) {
                return true;
            }
            return this.delete();
        }
    });
}

function hook_system_loadLibrary() {
    Java.perform(function () {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
        const VMStack = Java.use('dalvik.system.VMStack');

        SystemLoad_2.implementation = function (library) {
            send("Loading dynamic library => " + library);
            try {
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                if (library === 'myLib') {
                    //do my stuff
                }
                return loaded;
            } catch (ex) {
                console.log(ex);
            }
        };
    });
}

function hook_system_load() {
    Java.perform(function () {
        Java.use('java.lang.System').load.overload('java.lang.String').implementation = function (str) {
            send("Hooked system_load ,str: " + str);
            stackTrace();
            this.load(str);
        }
    });
}

function hook_assetManager_open() {
    Java.perform(function () {
        Java.use('android.content.res.AssetManager').open.overload('java.lang.String').implementation = function (filename) {
            send("Hooked assetManager_open ,fileName: " + filename);
            stackTrace2();
            return this.open(filename);
        }
    });
}

function hook_base64_decode(isTrace) {
    Java.perform(function () {
        var base64Cls = Java.use('android.util.Base64');
        base64Cls.decode.overload('[B', 'int').implementation = function (bArr, flag) {
            var output = this.decode(bArr, flag);
            send("Hooked base64_decode ,output: " + String.fromCharCode.apply(null, output));
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }

        base64Cls.decode.overload('java.lang.String', 'int').implementation = function (str, flag) {
            // if (str.indexOf("x86") != -1 || str.indexOf("arm") != -1) {
            //     send("got some: " + str);
            //     return this.decode("d293", flag);
            // }
            var output = this.decode(str, flag);
            send("Hooked base64_decode ,input: " + str + " ,output: " + bytesToString(output));
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }
    });
}

function hook_java_base64_encodeToString(isTrace) {
    Java.perform(function () {
        var base64Cls = Java.use('java.util.Base64$Encoder');
        base64Cls.encodeToString.overload('[B').implementation = function (bArr) {
            var output = this.encodeToString(bArr);
            send("Hooked hook_base64_encodeToString ,input: " + bytesToString(bArr) + ", output: " + output);
            if (isTrace) {
                stackTrace2();
            }
            return output;
        }
    });
}

function hook_telephonyManager_getSimOperator(mccMnc, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimOperator.overload().implementation = function () {
            let val = this.getSimOperator();
            send("Hooked telephonyManager_getSimOperator, value: " + val);
            if (isStackTrace) {
                stackTrace2();
            }
            if (mccMnc == '' || mccMnc == null) {
                val;
            }
            return mccMnc;
        }
    });
}

function hook_telephonyManager_getNwOperator(mccMnc, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkOperator.overload().implementation = function () {
            let val = this.getNetworkOperator()
            send("Hooked telephonyManager_getNetworkOperator, value: " + val);
            if (isStackTrace) {
                stackTrace2();
            }
            if (mccMnc == '' || mccMnc == null) {
                return val;
            }
            return mccMnc;
        }
    });
}

function hook_telephonyManager_getNetworkCountryIso1(countryShortName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkCountryIso.overload().implementation = function () {
            if (isStackTrace) {
                stackTrace2();
            }
            let origCountry = this.getNetworkCountryIso();
            send("Hooked telephonyManager_getNetworkCountryIso1, Country to return: " + countryShortName);
            if (countryShortName == '' || countryShortName == null) {
                return origCountry;
            }
            return countryShortName;
        }
    });
}

function hook_telephonyManager_getNetworkCountryIso2(countryShortName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkCountryIso.overload('int').implementation = function (slotIndex) {
            send("Hooked telephonyManager_getNetworkCountryIso2, Slot Index: " + slotIndex);
            if (isStackTrace) {
                stackTrace2();
            }
            if (countryShortName == '' || countryShortName == null) {
                return this.getNetworkCountryIso();
            }
            return countryShortName;
        }
    });
}

function hook_TelephonyManager_getSubsriberID1(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSubscriberId.overload().implementation = function () {
            var res = this.getSubscriberId();
            send("Hooked TelephonyManager_getSubsriberID1 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getSubsriberID2(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSubscriberId.overload('int').implementation = function (num) {
            var res = this.getSubscriberId(num);
            send("Hooked TelephonyManager_getSubsriberID2 ,Int: " + num + ", Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getDeviceId1(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getDeviceId.overload().implementation = function () {
            var res = this.getDeviceId();
            send("Hooked TelephonyManager_getDeviceId1 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_TelephonyManager_getDeviceId2(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getDeviceId.overload('int').implementation = function (num) {
            var res = this.getDeviceId(num);
            send("Hooked TelephonyManager_getDeviceId2 ,Res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            return res;
        }
    });
}

function hook_telephonyManager_getSimOperatorName(operatorName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimOperatorName.overload().implementation = function () {
            var res = this.getSimOperatorName();
            send("Hooked telephonyManager_getSimOperatorName, res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            if (operatorName == '' || operatorName == null) {
                return res;
            }
            return operatorName;
        }
    });
}

function hook_telephonyManager_getNetworkOperatorName(operatorName, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getNetworkOperatorName.overload().implementation = function () {
            var res = this.getNetworkOperatorName();
            send("Hooked telephonyManager_getNetworkOperatorName, res: " + res);
            if (isStackTrace) {
                stackTrace2();
            }
            if (operatorName == '' || operatorName == null) {
                return res;
            }
            return operatorName;
        }
    });
}

function hook_telephonyManager_getSimCountryIso(simCountryIso, isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimCountryIso.overload().implementation = function () {
            var res = this.getSimCountryIso();
            send("Hooked telephonyManager_getSimCountryIso, res: " + res + ", ToReturn: " + simCountryIso);
            if (isStackTrace) {
                stackTrace2();
            }
            return simCountryIso;
        }
    });
}

function hook_telephonyManager_getSimState(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').getSimState.overload().implementation = function () {
            var res = this.getSimState();
            send("Hooked telephonyManager_getSimState, default: " + res + ", ToReturn: " + 5);
            if (isStackTrace) {
                stackTrace2();
            }
            return 5;
        }
    });
}

function hook_telephonyManager_isNetworkRoaming(isStackTrace) {
    Java.perform(function () {
        Java.use('android.telephony.TelephonyManager').isNetworkRoaming.overload().implementation = function () {
            var res = this.isNetworkRoaming();
            send("Hooked telephonyManager_isNetworkRoaming, default: " + res + ", ToReturn: " + true);
            if (isStackTrace) {
                stackTrace2();
            }
            return true;
        }
    });
}

function hook_native_file_open() {
    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            if (filename.endsWith("meminfo") || filename.endsWith(".apk") || filename.endsWith(".so") || filename.endsWith(".dex") || filename.endsWith(".jar") || filename.indexOf("secondary-dexes") !== -1) {
                send('filename =' + filename)
                this.flag = true;
            }
        },
        onLeave: function (retval) {
            // if (this.flag) {
            //     send("Originl retval: " + retval);
            //     var newPath = "/data/data/com.re.reversershomeassignment/maps";
            //     var libcOpen = new NativeFunction(Module.findExportByName("libc.so", "open"), 'int', ['pointer', 'int']);
            //     var newPathPtr = Memory.allocUtf8String(newPath);
            //     var newFd = libcOpen(newPathPtr, 0);  // 0 is the default mode (O_RDONLY)
            //     send("New path: " + newPath);
            //     retval.replace(newFd);
            // }
        }
    });
}

function hook_native_file_dlopen() {
    Interceptor.attach(Module.findExportByName("libc.so", "dlopen"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            // send('dlopen - filename =' + filename)
            this.flag = true;
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
            send("dlopen - file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\nopen retval: " + retval);
        }
    });
}

const su_binaries = [
    "/su",
    "/su/bin/su",
    "/system/bin/androVM_setprop",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/system/bin/failsafe/su",
    "/system/bin/cufsdosck",
    "/system/xbin/cufsdosck",
    "/system/bin/cufsmgr",
    "/system/xbin/cufsmgr",
    "/system/bin/cufaevdd",
    "/system/xbin/cufaevdd",
    "/system/bin/conbb",
    "/system/xbin/conbb",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/data/app/com.topjohnwu.magisk",
    "/data/data/com.topjohnwu.magisk",
    "/data/user_de/0/com.topjohnwu.magisk",
    "/config/sdcardfs/com.topjohnwu.magisk",
    "/data/data/com.topjohnwu.magisk",
    "/config/sdcardfs/com.topjohnwu.magisk",
    "/data/media/0/Android/data/com.topjohnwu.magisk",
    "/mnt/runtime/default/emulated/0/Android/data/com.topjohnwu.magisk"]

function hook_native_file_stat() {
    Interceptor.attach(Module.findExportByName("libc.so", "stat"), {
        onEnter: function (args) {
            this.flag = false;
            var inputFile = Memory.readCString(ptr(args[0]));
            if (su_binaries.includes(inputFile)) {
                this.flag = true;
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
                send("stat - " + inputFile + " ]\nBacktrace:" + backtrace);
            }
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\netval: " + retval + " update response to -1");
            retval.replace(-1);
        }
    });
}

function hook_native_strstr() {
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
        onEnter: function (args) {
            this.flag = false;
            var haystack = Memory.readCString((args[0]));
            var needle = Memory.readCString((args[1]));
            this.flag = true;
            var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
            send("strstr - " + haystack + " " + needle + " ]\nBacktrace:" + backtrace);
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\netval: " + retval);
        }
    });
}

function hook_fileDelete_native() {
    Interceptor.attach(Module.findExportByName("libc.so", "unlink"), {
        onEnter: function (args) {
            this.flag = false;
            var filename = Memory.readCString(ptr(args[0]));
            if (filename.endsWith(".dex") || filename.endsWith(".jar") || filename.indexOf("secondary-dexes") !== -1) {
                send('Delete file, filename =' + filename)
                this.flag = true;
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
                send("file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
            }
        },
        onLeave: function (retval) {
            if (this.flag) // passed from onEnter
                send("\nretval: " + retval);
        }
    });
}

function hook_WebChromeClient_shouldOverrideUrlLoading() {
    Java.perform(function () {
        Java.use('android.webkit.WebViewClient').shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function (webView, str) {
            send("Hooked WebChromeClient_shouldOverrideUrlLoading, Str: " + str);
            // stackTrace();
            return this.shouldOverrideUrlLoading(webView, str);
        }
    });
}

function hook_webview_addJavascriptInterface() {
    Java.perform(function () {
        Java.use('android.webkit.WebView').addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, str) {
            send("Hooked webview_addJavascriptInterface ,obj Class: " + obj.getClass().getName() + ", str: " + str);
            // stackTrace();
            return this.addJavascriptInterface(obj, str);
        }
    });
}

function hook_webview_evaluateJavascript() {
    Java.perform(function () {
        Java.use('android.webkit.WebView').evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function (str, valCallback) {
            send("Hooked webview_evaluateJavascript ,str: " + str);
            stackTrace();
            return this.evaluateJavascript(str, valCallback);
        }
    });
}

function hook_webSettings_setJavaScriptEnabled() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').setJavaScriptEnabled.implementation = function (bool) {
            send("Hooked webSettings_setJavaScriptEnabled ,bool: " + bool);
            // stackTrace();
            return this.setJavaScriptEnabled(bool);
        }
    });
}

function hook_webSettings_getUserAgentString() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').getUserAgentString.implementation = function () {
            var userAgent = this.getUserAgentString();
            send("Hooked webSettings_getUserAgentString ,userAgent: " + userAgent);
            // stackTrace();
            return userAgent;
        }
    });
}

function hook_webSettings_setUserAgentString() {
    Java.perform(function () {
        Java.use('android.webkit.WebSettings').setUserAgentString.implementation = function (ua) {
            send("Hooked webSettings_setUserAgentString ,userAgent: " + ua);
            // stackTrace();
            return this.setUserAgentString(ua);
        }
    });
}

function process_killer() {
    Java.perform(function () {
        var procClass = Java.use('android.os.Process');
        var myPid = procClass.myPid();
        procClass.killProcess(myPid);
    });
}

function hook_Activity_onCreate() {
    Java.perform(function () {
        Java.use('android.app.Activity').onCreate.overload('android.os.Bundle').implementation = function (bundle) {
            send("#%#% Hooked Activity_onCreate, name: " + this.toString());
            return this.onCreate(bundle);
        }
    });
}

function hook_Activity_startActivity_1() {
    Java.perform(function () {
        Java.use('android.app.Activity').startActivity.overload('android.content.Intent').implementation = function (intent) {
            send("#%#% Hooked Activity_startActivity_1, Intent: " + intent);
            stackTrace();
            return this.startActivity(intent);
        }
    });
}

function hook_Activity_startActivity_2() {
    Java.perform(function () {
        Java.use('android.app.Activity').startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, bundle) {
            send("#%#% Hooked Activity_startActivity_2, Intent: " + intent + ", Bundle: " + bundle);
            stackTrace();
            return this.startActivity(intent, bundle);
        }
    });
}

function hook_Context_startActivity_1() {
    Java.perform(function () {
        Java.use('android.content.Context').startActivity.overload('android.content.Intent').implementation = function (intent) {
            send("#%#% Hooked Context_startActivity, Intent: " + intent);
            stackTrace();
            return this.startActivity(intent);
        }
    });
}

function hook_Context_startActivity_2() {
    Java.perform(function () {
        Java.use('android.content.Context').startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, bundle) {
            send("#%#% Hooked Context_startActivity_2, Intent: " + intent + ", Bundle: " + bundle);
            stackTrace();
            return this.startActivity(intent, bundle);
        }
    });
}

function hook_System_exit() {
    Java.perform(function () {
        Java.use('java.lang.System').exit.implementation = function (int) {
            send("Hooked System_exit, int: " + int);
            stackTrace();
            return;
            // return this.exit(int);
        }
    });
}

function hook_AdvertisingIdClient_Info_getId() {
    Java.perform(function () {
        Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info').getId.implementation = function () {
            var res = this.getId();
            send("Hooked AdvertisingIdClient_Info_getId, ad id: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_packageManager_queryIntentActivities() {
    Java.perform(function () {
        Java.use('android.content.pm.PackageManager').queryIntentActivities.overload('android.content.Intent', 'int').implementation = function (intent, flag) {
            var res = this.queryIntentActivities(intent, flag);
            send("Hooked packageManager_queryIntentActivities, intent: " + intent + ", Flag: " + flag + ", List length: " + res.size());
            stackTrace();
            return res;
        }
    });
}

function hook_hashMap_put() {
    Java.perform(function () {
        Java.use('java.util.HashMap').put.implementation = function (key, val) {
            send("Hooked hashMap_put, key: " + key + ", Val: " + val);
            return this.put(key, val);
        }
    });
}

function hook_Location_getLatitude() {
    Java.perform(function () {
        Java.use('android.location.Location').getLatitude.overload().implementation = function () {
            var res = this.getLatitude();
            send("Hooked Location_getLatitude, res: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_Location_getLongitude() {
    Java.perform(function () {
        Java.use('android.location.Location').getLongitude.overload().implementation = function () {
            var res = this.getLongitude();
            send("Hooked Location_getLongitude, res: " + res);
            stackTrace();
            return res;
        }
    });
}

function hook_VpnService_Builder_addAllowedApplication() {
    Java.perform(function () {
        Java.use('android.net.VpnService$Builder').addAllowedApplication.implementation = function (packageName) {
            send("Hooked VpnService_Builder_addAllowedApplication, package: " + packageName);
            this.addAllowedApplication("buhaha.scary.webview1");
            stackTrace();
            return this.addAllowedApplication(packageName);
        }
    });
}

function printArrOfObjects(oArr) {
    Java.perform(function () {
        var arraysClass = Java.use("java.util.Arrays");
        console.log("Arr Elements: " + arraysClass.toString(oArr));
    });
}

function hook_VpnService_prepare() {
    Java.perform(function () {
        Java.use('android.net.VpnService').prepare.implementation = function (ctx) {
            send("Hooked VpnService_prepare");
            stackTrace();
            return this.prepare(ctx);
        }
    });
}

function hook_NetworkCapabilities_vpnUsage() {
    Java.perform(function () {
        Java.use('android.net.NetworkCapabilities').hasTransport.implementation = function (transportType) {
            if (transportType == 4) {
                return false;
            }
            else {
                return this.hasTransport(transportType);
            }
        }
    });
}

function hook_fileOutputStream_init() {
    Java.perform(function () {
        Java.use('java.io.FileOutputStream').$init.overload('java.io.File').implementation = function (file) {
            console.log("Hooked fileOutputStream_init ,fileName: " + file.toString());
            stackTrace();
            return this.$init(file);
        }
    });
}

function hook_File_createNewFile() {
    Java.perform(function () {
        Java.use('java.io.File').createNewFile.implementation = function () {
            var path = this.getPath();
            // if (path.indexOf('dex') != -1 || path.indexOf('tmp') != -1 || path.indexOf('jar') != -1 || path.indexOf('dex') != -1) {
            console.log("Hooked File_createNewFile, path: " + path);
            stackTrace();
            // }
            return this.createNewFile();
        }
    });
}

function generateRandomAndroidId() {
    const hexChars = "0123456789abcdef";
    let androidId = "";
    for (let i = 0; i < 16; i++) {
        const randomIndex = Math.floor(Math.random() * hexChars.length);
        androidId += hexChars[randomIndex];
    }
    return androidId;
}


const sysVarsRes = { 'adb_enabled': "0", 'development_settings_enabled': "0", "android_id": "e4d98c34c25432f3" };
//const sysVarsRes = { 'adb_enabled': "0", };

function SysPropsBypass(isStackTrace) {
    var Secure = Java.use('android.provider.Settings$Secure');
    var System = Java.use('android.provider.Settings$System');
    var Global = Java.use('android.provider.Settings$Global');

    Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }
    System.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    System.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }
    Global.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, str, int) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str, int);
        }
    }
    Global.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getInt(cr, str);
        }
    }

    Secure.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    Secure.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }
    System.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    System.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }
    Global.getFloat.overload('android.content.ContentResolver', 'java.lang.String', 'float').implementation = function (cr, str, fl) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str, fl);
        }
    }
    Global.getFloat.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getFloat(cr, str);
        }
    }

    Secure.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    Secure.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }
    System.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    System.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }
    Global.getLong.overload('android.content.ContentResolver', 'java.lang.String', 'long').implementation = function (cr, str, lng) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str, lng);
        }
    }
    Global.getLong.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getLong(cr, str);
        }
    }

    Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Secure - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }
    System.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings System - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }
    Global.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, str) {
        if (str in sysVarsRes) {
            send("Settings Global - Input value: " + str);
            if (isStackTrace) {
                stackTrace2();
            }
            return sysVarsRes[str];
        } else {
            return this.getString(cr, str);
        }
    }

    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        console.warn('[*] Debug.isDebuggerConnected() Bypass !');
        return false;
    }
}

function antiFridaBypass() {
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

        onEnter: function (args) {

            this.haystack = args[0];
            this.needle = args[1];
            this.frida = Boolean(0);

            haystack = Memory.readUtf8String(this.haystack);
            needle = Memory.readUtf8String(this.needle);

            if (haystack.indexOf("frida") !== -1 || haystack.indexOf("xposed") !== -1) {
                this.frida = Boolean(1);
            }
        },

        onLeave: function (retval) {

            if (this.frida) {
                retval.replace(0);
            }
            return retval;
        }
    });
}

function flock_hook(isTrace) {
    Interceptor.attach(Module.findExportByName("libc.so", "flock"), {

        onEnter: function (args) {
            console.log("flock onEnter, pid: " + Process.id);
            if (isTrace) {
                send('flock_hook called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        },

        onLeave: function (retval) {
            console.log("flock onLeave");
            return retval;
        }
    });
}

function fork_hook(isTrace) {
    Interceptor.attach(Module.findExportByName("libc.so", "fork"), {

        onEnter: function (args) {
            console.log("flock onEnter, pid: " + Process.id + ", file Descriptor: " + args[0].toInt32());
            if (isTrace) {
                send('flock_hook called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
            }
        },

        onLeave: function (retval) {
            console.log("fork onLeave");
            return retval;
        }
    });
}

function hook_getCookie() {
    const cookieManager = 'android.webkit.CookieManager';
    const cookieManagerCls = Java.use(cookieManager);
    cookieManagerCls.getInstance.overload().implementation = function () {
        const instance = this.getInstance();
        const cls = instance.getClass();
        const dynamicGeneratedCls = Java.ClassFactory.get(cls.getClassLoader()).use(cls.getName());
        dynamicGeneratedCls.getCookie.overload('java.lang.String').implementation = function (url) {
            const cookie = Java.cast(this, cookieManagerCls).getCookie(url);
            console.log("getCookie Hooked. URL: " + url + ". Cookie: " + cookie);
            return cookie;
        }
        return instance;
    }
}

function cellularHooks(isTrace) {
    // SIM Info
    // var mMccMnc = "40433";
    // var mShortCountryName = "in";
    // var mMccMnc = "310260";
    // var mShortCountryName = "us";
    // var mMccMnc = "43102";
    // var mShortCountryName = "ae";
    // var mMccMnc = "43220";
    // var mShortCountryName = "ir";
    // var mMccMnc = "42007"; // Zain
    // var operatorName = "Zain"
    // var mShortCountryName = "sa";
    // var mMccMnc = "25505";
    // var mShortCountryName = "ua";
    // var mMccMnc = "46007";
    // var mShortCountryName = "cn";
    // var mMccMnc = "23436";
    // var mShortCountryName = "gb";
    //---------------------------------
    // var mMccMnc = "45201";
    // var operatorName = "MobiFone";
    // var mShortCountryName = "vn";
    //---------------------------------
    // var mMccMnc = "20825";
    // var operatorName = "Lycamobile";
    // var mShortCountryName = "fr";
    //---------------------------------
    // var mMccMnc = "25034";
    // var operatorName = "Krymtelecom";
    // var mShortCountryName = "ru";
    //---------------------------------
    // var mMccMnc = "45411";
    // var operatorName = "China-Hong Kong Telecom";
    // var mShortCountryName = "hk";
    //---------------------------------
    // var mMccMnc = "22610";
    // var operatorName = "Orange";
    // var mShortCountryName = "ro";
    //---------------------------------
    // var mMccMnc = "52005"; // dtac TriNet / LINE
    // var operatorName = "DTAC";
    // var mShortCountryName = "th";
    //---------------------------------
    var mMccMnc = "52018"; // DTAC
    var operatorName = "DTAC";
    var mShortCountryName = "th";
    //---------------------------------
    // var mMccMnc = "52003"; // AIS/Advanced Info Service
    // var operatorName = "AIS";
    // var mShortCountryName = "th";
    //---------------------------------
    // var mMccMnc = "50216"; // Digi Telecommunications
    // var operatorName = "digi";
    // var mShortCountryName = "my";
    //---------------------------------
    // var mMccMnc = "50219"; // CelCom
    // var operatorName = "Celcom";
    // var mShortCountryName = "my";
    //---------------------------------
    // var mMccMnc = "23002"; // O2
    // var operatorName = "O2";
    // var mShortCountryName = "cz";
    //---------------------------------
    // var mMccMnc = "23402"; // O2
    // var operatorName = "O2";
    // var mShortCountryName = "gb";
    //---------------------------------
    // var mMccMnc = "42404";
    // var mShortCountryName = "ae";
    // var operatorName = "Etisalat"
    // ---------------------------------
    // var mMccMnc = "42403";
    // var mShortCountryName = "ae";
    // var operatorName = "DU"
    //---------------------------------
    // var mMccMnc = "334010"; // AT&T
    // var operatorName = "att";
    // var mShortCountryName = "mx";
    //---------------------------------
    // var mMccMnc = "22206"; // Vodafone
    // var operatorName = "vodafone";
    // var mShortCountryName = "it";
    //---------------------------------
    // var mMccMnc = "724299";
    // var operatorName = "Cinco";
    // var mShortCountryName = "br";
    //---------------------------------
    // var mMccMnc = "42508"; // Golan Telecom
    // var operatorName = "Golan";
    // var mShortCountryName = "il";
    //---------------------------------
    // var mMccMnc = "25099";
    // var operatorName = "Beeline";
    // var mShortCountryName = "ru";
    //---------------------------------
    // var mMccMnc = "28601";
    // var operatorName = "Turkcell";
    // var mShortCountryName = "tr";
    //---------------------------------
    // var mMccMnc = "41003";
    // var operatorName = "Ufone";
    // var mShortCountryName = "pk";
    //---------------------------------
    // var mMccMnc = "40433";
    // var operatorName = "Aircel";
    // var mShortCountryName = "in";
    //---------------------------------
    // var mMccMnc = "312210";
    // var operatorName = "AT&T Mobility";
    // var mShortCountryName = "us";
    //---------------------------------
    // var mMccMnc = "25501";
    // var operatorName = "Vodafone";
    // var mShortCountryName = "ua";

    var isStackTrace = isTrace;
    hook_telephonyManager_getSimState(isTrace);
    hook_telephonyManager_isNetworkRoaming(isTrace);

    hook_telephonyManager_getSimCountryIso(mShortCountryName, isStackTrace);
    hook_telephonyManager_getSimOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNwOperator(mMccMnc, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso1(mShortCountryName, isStackTrace);
    hook_telephonyManager_getNetworkCountryIso2(mShortCountryName, isStackTrace);

    hook_TelephonyManager_getSubsriberID1(isStackTrace);
    hook_TelephonyManager_getSubsriberID2(isStackTrace);
    hook_TelephonyManager_getDeviceId1(isStackTrace);
    hook_TelephonyManager_getDeviceId2(isStackTrace);

    hook_telephonyManager_getSimOperatorName(operatorName, isStackTrace);
    hook_telephonyManager_getNetworkOperatorName(operatorName, isStackTrace);
}

function hook_InputMethodSubtype_getLanguageTag(retVal) {
    Java.perform(function () {
        Java.use('android.view.inputmethod.InputMethodSubtype').getLanguageTag.implementation = function () {
            let locale = this.getLanguageTag();
            send('Hooked InputMethodSubtype getLanguageTag, value: ' + locale);
            if (retVal != null && retVal.length > 0) {
                return retVal;
            }
            return this.getLanguageTag();
        }
    });
}

function hook_TimeZone_getDefault(retVal) {
    Java.perform(function () {
        let tz = Java.use('android.icu.util.TimeZone');
        tz.getDefault.implementation = function () {
            let tz = this.getDefault();
            send('Hooked android.icu.util.TimeZone_getDefault, value: ' + tz.getID());
            if (retVal != null && retVal.length > 0) {
                return tz.getTimeZone(retVal);
            }
            stackTrace();
            return tz;
        }
    });
}

function hook_TimeZone2_getDefault(retVal) {
    Java.perform(function () {
        let tz = Java.use('java.util.TimeZone');
        tz.getDefault.implementation = function () {
            let tz = this.getDefault();
            send('Hooked java.util.TimeZone_getDefault, value: ' + tz.getID());
            if (retVal != null && retVal.length > 0) {
                return tz.getTimeZone(retVal);
            }
            stackTrace();
            return tz;
        }
    });
}

function hook_account_init() {
    Java.perform(function () {
        Java.use('android.accounts.Account').$init.overload('java.lang.String', 'java.lang.String').implementation = function (name, type) {
            send('Hooked account_init, name: ' + name + ' , type: ' + type);
            return this.$init(name, type);
        }
    });
}

function hook_AccountManager_addAccountExplicitly() {
    Java.perform(function () {
        let addAcountEx = Java.use('android.accounts.AccountManager').addAccountExplicitly.overload('android.accounts.Account', 'java.lang.String', 'android.os.Bundle');
        addAcountEx.implementation = function (account, pass, userData) {
            let ps = '';
            if (pass != null) {
                ps = pass;
            }
            send('Hooked AccountManager_addAccountExplicitly, account: ' + account.toString() + ' , pass: ' + ps + ', bundle: ' + userData);
            return this.addAccountExplicitly(account, pass, userData);
        }
    });
}

function hook_ContentResolver_isSyncPending() {
    Java.perform(function () {
        let isSyncPen = Java.use('android.content.ContentResolver').isSyncPending;
        isSyncPen.implementation = function (account, authority, extras) {
            let res = this.isSyncPending(account, authority);
            send('Hooked ContentResolver_isSyncPending, account: ' + account + ' , authority: ' + authority + ', res: ' + res);
            return res;
        }
    });
}

function hook_ContentResolver_requestSync() {
    Java.perform(function () {
        let reqSync = Java.use('android.content.ContentResolver').requestSync.overload('android.accounts.Account', 'java.lang.String', 'android.os.Bundle');
        reqSync.implementation = function (account, authority, extras) {
            send('Hooked ContentResolver_requestSync, account: ' + account + ' , authority: ' + authority + ' , extras: ' + extras);
            return this.requestSync(account, authority, extras);
        }
    });
}

function hook_ContentResolver_addPeriodicSync() {
    Java.perform(function () {
        Java.use('android.content.ContentResolver').addPeriodicSync.implementation = function (account, authority, extras, pollFreq) {
            send('Hooked ContentResolver_addPeriodicSync, account: ' + account + ' , authority: ' + authority + ' , extras: ' + extras + ' , pollFreq: ' + pollFreq);
            return this.addPeriodicSync(account, authority, extras, pollFreq);
        }
    });
}

function hook_BluetoothAdapter_getBondedDevices() {
    Java.perform(function () {
        Java.use('android.bluetooth.BluetoothAdapter').getBondedDevices.implementation = function () {
            let bondedDevices = this.getBondedDevices();
            send('Hooked BluetoothAdapter_getBondedDevices, size: ' + bondedDevices.size());
            let hashSet = Java.use('java.util.HashSet');
            let BTDev = Java.use('android.bluetooth.BluetoothDevice');
            let BTDevObj = BTDev.$new('00:11:22:33:EE:FF');
            let newBondedDevices = hashSet.$new();
            newBondedDevices.add(BTDevObj);
            return newBondedDevices;
        }
    });
}

function hook_PackageManager_getInstallerPackageName() {
    Java.perform(function () {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        PackageManager.getInstallerPackageName.overload("java.lang.String").implementation = function (packageName) {
            var returnVal = this.getInstallerPackageName(packageName);
            send("hook_PackageManager_getInstallerPackageName, package: " + packageName + ", return value: " + returnVal);
            var playInstallerPackage = "com.android.vending";
            send("Returning Play installer package: " + playInstallerPackage);
            return playInstallerPackage;
        };
    });
}

function traceClasses() {
    Java.perform(function () {
        // Java.enumerateLoadedClassesSync();
        // Trace all
        [
            // "com.re.reversershomeassignment.MainActivity"
            // "android.content.SharedPreferences$Editor",
            // "android.content.SharedPreferences",
            // "android.content.ContentValues",
            // "org.json.JSONObject",
            // "org.json.JSONArray",
            // "com.google.android.gms.location.FusedLocationProviderClient",

            // "com.tencent.mmkv.MMKV"

            // "com.reactnativecommunity.cookies.CookieManagerModule",
            // "com.reactnativecommunity.webview.RNCWebView",
            // "com.reactnativecommunity.cookies.CookieManagerModule",

            // "io.grpc.okhttp.OkHttpChannelBuilder$OkHttpTransportFactory",
            // "io.grpc.internal.InternalSubchannel",
            // "io.grpc.internal.ChannelLoggerImpl"

            // "android.util.Base64",

            // "android.os.SystemClock"

        ].forEach(traceClass);
    });
}

function hook_installTimeUpdate(hoursDiff) {
    Java.perform(function () {
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var sys = Java.use('java.lang.System');
        var timeDiff = 3600000 * hoursDiff;
        var pm = context.getPackageManager();
        var pn = context.getPackageName();
        var pi = pm.getPackageInfo(pn, 0);
        var newTime = sys.currentTimeMillis() - timeDiff;
        console.log("Update first install time " + hoursDiff + " hours back");
        pi.firstInstallTime.value = newTime;
    });
}

function waitForDebugger() {
    Java.perform(function () {
        // var attachBasectx = Java.use('android.app.Application').attachBaseContext;
        var attachBasectx = Java.use('android.content.ContextWrapper').attachBaseContext;

        attachBasectx.implementation = function (ctx) {
            console.log("[+] Waiting for debugger to attach!");
            while (!Process.isDebuggerAttached()) {
            }
            console.log("[+] Debugger attached!");
            return this.attachBaseContext(ctx);
        }
    });
}

// Unity
function unity_printBridgeMsg() {
    let com_unity3d_player_UnityPlayer = Java.use('com.unity3d.player.UnityPlayer');
    com_unity3d_player_UnityPlayer.nativeUnitySendMessage.overload("java.lang.String", "java.lang.String", "[B").implementation = function (arg0, arg1, arg2) {
        console.log(`[+] Hooked com.unity3d.player.UnityPlayer.nativeUnitySendMessage: arg0=${arg0}, arg1=${arg1}, arg2=${String.fromCharCode.apply(String, arg2)}`);
        this['nativeUnitySendMessage'](arg0, arg1, arg2);
    };
}

function newUnityStr(input) {
    const il2cpp_string_new = new NativeFunction(
        Module.findExportByName('libil2cpp.so', 'il2cpp_string_new'),
        'pointer',
        ['pointer']
    );

    // Step 2: Create a new C string
    const newCString = Memory.allocUtf8String(input);

    // Step 3: Create a new System_String object
    const unityStr = il2cpp_string_new(newCString);

    return unityStr;
}

function unityToJSStr(unityStr) {
    if (!unityStr.isNull()) {
        const stringObject = unityStr;

        // IL2CPP header size and string length offset might differ based on the target architecture
        const headerSize = 0x10; // Assuming a common header size
        const lengthOffset = headerSize; // Length is right after the header
        const length = stringObject.add(lengthOffset).readInt(); // Read the length of the string

        if (length > 0) {
            // UTF-16 characters start right after the length field
            const utf16Chars = stringObject.add(lengthOffset + 4);
            const jsString = utf16Chars.readUtf16String(length);
            return jsString;
        } else {
            send('Returned string is empty');
        }
    } else {
        send('Returned string is null');
    }
    return '';
}

function unity_string_toLower() {
    send('Hooking unity_string_toLower');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xB9FD40');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_string_toLower Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("unity_string_toLower Leave, response: " + jstr);
        }
    });
}


function UnityEngine_SystemInfo_GetDeviceModel() {
    send('Hooking unity_string_toLower');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xFACFF8');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("UnityEngine_SystemInfo_GetDeviceModel Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("UnityEngine_SystemInfo_GetDeviceModel Leave, response: " + jstr);
            if (jstr.indexOf('Google') > -1) {
                let toReplace = jstr.replace('Google', 'Boogle');
                send("unity_string_toLower Leave, replacing to: " + toReplace);
                let newVal = newUnityStr(toReplace);
                retval.replace(newVal);
            }
        }
    });
}

function unity_TimeZoneInfo_getDisplayName() {
    send('Hooking unity_TimeZoneInfo_getDisplayName');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA788C');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_TimeZoneInfo_getDisplayName Enter");
        },
        onLeave(retval) {
            let jstr = unityToJSStr(retval);
            send("unity_TimeZoneInfo_getDisplayName Leave, response: " + jstr);
            let newVal = newUnityStr('(GMT-01:00) Local Time');
            retval.replace(newVal);

        }
    });
}

function unity_String_Contains() {
    send('Hooking unity_String_Contains');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA037C');
    Interceptor.attach(offset, {
        onEnter(args) {
            var first = unityToJSStr(args[0]);
            var second = unityToJSStr(args[1]);
            send("unity_String_Contains Enter, first: " + first + ", second: " + second);

        },
        onLeave(retval) {
            if (retval.isNull()) {
                console.log('Returned boolean: null');
            } else {
                try {
                    // Assuming the return value is a boolean stored as a single byte
                    const nativeBool = retval.toUInt32() & 0xFF;  // Read the byte value
                    const jsBool = nativeBool !== 0;
                    console.log('unity_String_Contains - Returned boolean: ' + jsBool);
                } catch (e) {
                    console.log('Error reading returned boolean: ' + e);
                }
            }
        }
    });
}

function unity_TimeZoneInfo_getLocal() {
    send('Hooking unity_TimeZoneInfo_getLocal');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xBA488C');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("unity_TimeZoneInfo_getLocal Enter");
        },
        onLeave(retval) {
            send("unity_TimeZoneInfo_getLocal Leave");
            if (!retval.isNull()) {
                const timeZoneInfo = retval;

                // Assuming header size for IL2CPP object is 0x10 (this can vary)
                const headerSize = 0x10;

                // Offsets of fields within TimeZoneInfo
                const idOffset = headerSize + 0x8; // Adjust based on actual structure
                const baseUtcOffsetOffset = headerSize + 0x10; // Adjust based on actual structure

                // Read the id field (System.String)
                const idPtr = timeZoneInfo.add(idOffset).readPointer();
                const idLengthOffset = 0x10; // Assuming string length is at 0x10 from the start of the string object
                const idLength = idPtr.add(idLengthOffset).readInt();
                const idChars = idPtr.add(idLengthOffset + 4); // Assuming UTF-16 chars start after the length field
                const id = idChars.readUtf16String(idLength);

                // Read the baseUtcOffset field (TimeSpan struct, assuming Ticks is at the start)
                const baseUtcOffsetTicks = timeZoneInfo.add(baseUtcOffsetOffset).readS64();

                console.log('TimeZoneInfo ID: ' + id);
                console.log('Base UTC Offset Ticks: ' + baseUtcOffsetTicks);
            } else {
                console.log('Returned TimeZoneInfo is null');
            }
        }
    });
}

function unityEngine_AndroidJavaObject_call() {
    send('Hooking UnityEngine_AndroidJavaObject__Call');
    var base = Module.getBaseAddress('libil2cpp.so');
    var offset = base.add('0xF89658');
    Interceptor.attach(offset, {
        onEnter(args) {
            send("UnityEngine_AndroidJavaObject__Call Enter");
            const androidJavaObjectPtr = args[0];

            const jobjectPtrOffset = 0x18;
            const jobjectPointer = androidJavaObjectPtr.add(jobjectPtrOffset);
            let clsName = unityToJSStr(jobjectPointer);
            console.log('Class name:' + clsName);

            let methodName = unityToJSStr(args[1]);
            console.log('Method name:' + methodName);
        },
        onLeave(retval) {
            send("UnityEngine_AndroidJavaObject__Call Leave");
        }
    });
}

function waitForLibLoading(libraryName) {
    var isLibLoaded = false;
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var libraryPath = Memory.readCString(args[0]);
            if (libraryPath.includes(libraryName)) {
                console.log("[+] Loading library " + libraryPath + "...");
                isLibLoaded = true;
            }
        },
        onLeave: function (args) {
            if (isLibLoaded) {
                isLibLoaded = false;
            }
        }
    });
}

function waitForLoad(libName) {
    var baseAdrr;
    var interv = setInterval(function () {
        baseAdrr = Module.findBaseAddress(libName);
        if (baseAdrr) {
            send('Loaded lib: ' + libName);
            clearInterval(interv);
            hookNativeMethods();
        }
    }, 10);
}

function hookNativeMethods() {
    // unity_string_toLower();
    // unity_TimeZoneInfo_getLocal();
    // unity_TimeZoneInfo_getDisplayName();
    // unity_String_Contains();
    // UnityEngine_SystemInfo_GetDeviceModel();
    unityEngine_AndroidJavaObject_call();
}

function printJSMap(map) {
    // Check if the input is a Map
    if (!(map instanceof Map)) {
        console.log("Input is not a Map.");
        return;
    }

    // Iterate over the map entries
    for (const [key, value] of map.entries()) {
        console.log(`${key}: ${value}`);
    }
}

function printJSObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        console.log("Input is not a valid object.");
        return;
    }

    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            console.log(`${key}: ${obj[key]}`);
        }
    }
}

function printCurrentBuildValues() {
    var buildCls = Java.use('android.os.Build');

    send("Current Build values:");
    send("BOARD: " + buildCls.BOARD.value);
    send("BOOTLOADER: " + buildCls.BOOTLOADER.value);
    send("BRAND: " + buildCls.BRAND.value);
    send("DEVICE: " + buildCls.DEVICE.value);
    send("DISPLAY: " + buildCls.DISPLAY.value);
    send("FINGERPRINT: " + buildCls.FINGERPRINT.value);
    send("HARDWARE: " + buildCls.HARDWARE.value);
    send("HOST: " + buildCls.HOST.value);
    send("ID: " + buildCls.ID.value);
    send("MANUFACTURER: " + buildCls.MANUFACTURER.value);
    send("MODEL: " + buildCls.MODEL.value);
    send("PRODUCT: " + buildCls.PRODUCT.value);
    send("TAGS: " + buildCls.TAGS.value);
    send("TYPE: " + buildCls.TYPE.value);
    send("USER: " + buildCls.USER.value);

    // SERIAL is deprecated in newer Android versions and may be inaccessible:
    // send("SERIAL: " + buildCls.SERIAL.value);
}

function updateBuildInfo(valuesMap) //printJSObject(valuesMap);
{

    printCurrentBuildValues();

    send("Updated Build values:")
    printJSObject(valuesMap);

    var buildCls = Java.use('android.os.Build');

    // Each field is static, so we assign to .value
    // Only assign if the key exists in the map to avoid overwriting with undefined
    if ('BOARD' in valuesMap) buildCls.BOARD.value = valuesMap['BOARD'];
    if ('BOOTLOADER' in valuesMap) buildCls.BOOTLOADER.value = valuesMap['BOOTLOADER'];
    if ('BRAND' in valuesMap) buildCls.BRAND.value = valuesMap['BRAND'];
    if ('DEVICE' in valuesMap) buildCls.DEVICE.value = valuesMap['DEVICE'];
    if ('DISPLAY' in valuesMap) buildCls.DISPLAY.value = valuesMap['DISPLAY'];
    if ('FINGERPRINT' in valuesMap) buildCls.FINGERPRINT.value = valuesMap['FINGERPRINT'];
    if ('HARDWARE' in valuesMap) buildCls.HARDWARE.value = valuesMap['HARDWARE'];
    if ('HOST' in valuesMap) buildCls.HOST.value = valuesMap['HOST'];
    if ('ID' in valuesMap) buildCls.ID.value = valuesMap['ID'];
    if ('MANUFACTURER' in valuesMap) buildCls.MANUFACTURER.value = valuesMap['MANUFACTURER'];
    if ('MODEL' in valuesMap) buildCls.MODEL.value = valuesMap['MODEL'];
    if ('PRODUCT' in valuesMap) buildCls.PRODUCT.value = valuesMap['PRODUCT'];
    if ('TAGS' in valuesMap) buildCls.TAGS.value = valuesMap['TAGS'];
    if ('TYPE' in valuesMap) buildCls.TYPE.value = valuesMap['TYPE'];
    if ('USER' in valuesMap) buildCls.USER.value = valuesMap['USER'];

    // Some fields like `SERIAL` or `TIME` may be device or API level dependent
    // Check the Android docs if you need to modify them. SERIAL often requires special handling.
    if ('SERIAL' in valuesMap) {
        // On modern Android versions, Build.SERIAL is deprecated and read-only.
        // Frida may still let you set it, but it won't necessarily reflect in the system.
        buildCls.SERIAL.value = valuesMap['SERIAL'];
    }
}

function getBuildProfile(profileName) {
    const pixel6 = {
        MANUFACTURER: 'Google',
        MODEL: 'Pixel 6',
        BRAND: 'google',
        DEVICE: 'oriole',
        PRODUCT: 'oriole',
        FINGERPRINT: 'google/oriole/oriole:12/SP2A.220305.013.A3/8229987:user/release-keys',
        HARDWARE: 'oriole',
        ID: 'SP2A.220305.013.A3',
        DISPLAY: 'SP2A.220305.013.A3',
        TYPE: 'user'
    };

    // Samsung Galaxy S22 (Example values; may not match exact released builds)
    const samsungS22 = {
        MANUFACTURER: 'Samsung',
        MODEL: 'SM-S901B',
        BRAND: 'samsung',
        DEVICE: 'r0',
        PRODUCT: 'r0xx',
        // Example fingerprint pattern; replace with actual known fingerprint if available
        FINGERPRINT: 'samsung/r0xx/r0:13/TP1A.220905.004/9999999:user/release-keys',
        HARDWARE: 'qcom',
        ID: 'TP1A.220905.004',
        DISPLAY: 'TP1A.220905.004',
        TYPE: 'user'
    };

    // OnePlus Nord 3 (Example values)
    const onePlusNord3 = {
        MANUFACTURER: 'OnePlus',
        MODEL: 'CPH2493',
        BRAND: 'OnePlus',
        DEVICE: 'CPH2493',
        PRODUCT: 'CPH2493EEA',
        // Example fingerprint pattern; replace with actual known fingerprint if available
        FINGERPRINT: 'OnePlus/CPH2493EEA/CPH2493:13/EB210210209/1234567:user/release-keys',
        HARDWARE: 'mt6894',
        ID: 'EB210210209',
        DISPLAY: 'EB210210209',
        TYPE: 'user'
    };

    const googleEmulator = {
        MANUFACTURER: 'Google',
        MODEL: 'sdk_gphone64_x86_64',
        BRAND: 'google',
        DEVICE: 'emulator64_x86_64_arm64',
        PRODUCT: 'sdk_gphone64_x86_64',
        FINGERPRINT: 'google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys',
        HARDWARE: 'ranchu',
        ID: 'SE1B.220616.007',
        DISPLAY: 'sdk_gphone64_x86_64-userdebug 12 SE1B.220616.007 10056955 dev-keys',
        TYPE: 'userdebug'
    };

    const profilesMap = {
        "pixel6": pixel6,
        "samsungS22": samsungS22,
        "onePlusNord3": onePlusNord3,
        "androidStudioEmulator": googleEmulator,
    };

    return profilesMap[profileName] || null;
}

function hook_firestore_DocumentSnapshot_get(keyStr, newVal) {
    Java.perform(function () {
        Java.use('com.google.firebase.firestore.DocumentSnapshot').get.overload('java.lang.String').implementation = function (key) {
            var resObj = this.get(key);
            send('Hooked firestore_DocumentSnapshot_get, key: ' + key + ", return: " + resObj);
            if (keyStr != null && newVal != null && keyStr != undefined && newVal != undefined && key == keyStr) {
                var jvar;
                if (typeof (newVal) == 'boolean') {
                    jvar = Java.use('java.lang.Boolean').$new(newVal);
                }
                if (typeof (newVal) == 'string') {
                    jvar = Java.use('java.lang.String').$new(newVal);
                }
                if (typeof (newVal) == 'number') {
                    jvar = Java.use('java.lang.Integer').$new(newVal);
                }
                if (jvar != null) {
                    var objVal = Java.cast(jvar, Java.use('java.lang.Object'));
                    send('Hooked firestore_DocumentSnapshot_get, override values: key: ' + keyStr + ", return: " + newVal);
                    return objVal;
                }
            }
            return resObj;
        }
    });
}

function hook_firestore_QueryDocumentSnapshot_getData(keyStr, newVal) {
    Java.perform(function () {
        Java.use('com.google.firebase.firestore.QueryDocumentSnapshot').getData.overload().implementation = function () {
            var map = this.getData();
            send('Hooked firestore_QueryDocumentSnapshot_getData, map:');
            if (keyStr !== null && newVal !== null && keyStr !== undefined && newVal !== undefined) {
                UpdateHashMap(map, keyStr, newVal);
            } else {
                printHashMap(map);
            }
            return map;
        }
    });
}

function hook_NetworkCapabilities_hasTransport() {
    Java.perform(function () {
        Java.use('android.net.NetworkCapabilities').hasTransport.overload('int').implementation = function (typeInt) {
            var res = this.hasTransport(typeInt);
            send('Hooked NetworkCapabilities_hasTransport, typeInt: ' + typeInt + ", response: " + res);
            if (typeInt == 4) {
                send('VPN check, return false');
                return false;
            }
            return res;
        }
    });
}

function hook_NetworkInterface_getName() {
    Java.perform(function () {
        Java.use('java.net.NetworkInterface').getName.overload().implementation = function () {
            var res = this.getName();
            send('Hooked NetworkInterface_getName, name: ' + res);
            if (res == 'tun0' || res == 'ppp0') {
                send('Hooked NetworkInterface_getName, return value: dummy0');
                return 'dummy0';
            }
            return res;
        }
    });
}

function hook_ReferrerDetails_getInstallReferrer(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallReferrer.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallReferrer`);
            let result = this['getInstallReferrer']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallReferrer result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallReferrer value to return=${result}`);
            }
            // stackTrace2();
            return result;
        };
    });
}

function hook_ReferrerDetails_getReferrerClickTimestampServerSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getReferrerClickTimestampServerSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds`);
            let result = this['getReferrerClickTimestampServerSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampServerSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getInstallBeginTimestampServerSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallBeginTimestampServerSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds`);
            let result = this['getInstallBeginTimestampServerSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampServerSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getReferrerClickTimestampSeconds(newVal) {
    Java.perform(function () {
        var com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getReferrerClickTimestampSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds`);
            let result = this['getReferrerClickTimestampSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_ReferrerDetails_getInstallBeginTimestampSeconds(newVal) {
    Java.perform(function () {
        let com_android_installreferrer_api_ReferrerDetails = Java.use('com.android.installreferrer.api.ReferrerDetails');
        com_android_installreferrer_api_ReferrerDetails.getInstallBeginTimestampSeconds.overload().implementation = function () {
            console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampSeconds`);
            let result = this['getInstallBeginTimestampSeconds']();
            console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getInstallBeginTimestampSeconds result=${result}`);
            if (newVal !== null && newVal !== undefined) {
                result = newVal;
                console.log(`[+] com.android.installreferrer.api.ReferrerDetails.getReferrerClickTimestampSeconds value to return=${result}`);
            }
            return result;
        }
    });
}

function hook_BatteryManager_getIntProperty() {
    Java.perform(function () {
        let batteryManager = Java.use('android.os.BatteryManager');
        batteryManager.getIntProperty.overload('int').implementation = function (propId) {
            let result = this['getIntProperty'](propId);
            send("[+] Hooked BatteryManager_getIntProperty, property int: " + propId + ", result: " + result);
            let fakePercentage = 89
            send("[+] Hooked BatteryManager_getIntProperty, fake percentage: " + fakePercentage);
            if (result > 90) {
                return fakePercentage;
            }
            return result;
        };
    });
}

function hook_StringBuilder_append() {
    Java.perform(function () {
        var strBldCls = Java.use('java.lang.StringBuilder');

        strBldCls.append.overloads.forEach(function (overload, index) {
            // Check if the overload takes 'java.lang.String' as the only argument
            if (overload.argumentTypes.length === 1 && overload.argumentTypes[0].className === 'java.lang.String') {
                console.log("[+] Hooking Overload " + index + ": StringBuilder.append(String)");

                overload.implementation = function (str) {
                    // Call the original implementation
                    let result = this.append(str);
                    // Example logic: Check for specific string pattern
                    if (str.endsWith('/su') || str === "\n") {
                        console.log("[*#*] Overload " + index + ": StringBuilder.append(String) called with: " + str);
                        var emptyStrBld = strBldCls.$new("");
                        console.log("[*#*] sizeof empty strBld " + emptyStrBld.length());
                        return emptyStrBld; // Return a new empty StringBuilder
                    }
                    return result; // Return the original result
                };
            }
        });
    });
}

function hook_StringBuilder_length() {
    Java.perform(function () {
        var StringBuilder = Java.use('java.lang.StringBuilder');

        // Hook the `length()` method
        StringBuilder.length.overloads.forEach(function (overload, index) {
            console.log("[*] Hooking StringBuilder.length overload " + index);

            overload.implementation = function () {
                // Log when the method is called

                // Call the original implementation
                var result = overload.apply(this, arguments);

                if (this.toString().indexOf('/su') != -1) {
                    console.log("[*#*] StringBuilder value: " + this.toString());
                    console.log("[*#*] StringBuilder return length 0");
                    result = 0;
                }

                return result; // Return the original length
            };
        });
    });

}

function wifiNetwork_hook() {
    Java.perform(function () {

        // Network override

        var classx = Java.use("android.net.ConnectivityManager");
        var networkInfo = classx.getActiveNetworkInfo;
        networkInfo.implementation = function (args) {
            console.log('[!] Hook getActiveNetworkInfo()');
            var netInfo = networkInfo.call(this);
            // console.log('\t[!] netInfo1: ' + netInfo);
            // when use SIM
            // [!] returnVal:[type: MOBILE[LTE], state: CONNECTED/CONNECTED, reason: (unspecified), extra: internet, failover: false, available: true, roaming: false]
            // return  networkInfo.call(this);

            var networkInfo_class = Java.use("android.net.NetworkInfo");
            // var networkInfo2 = networkInfo2.$new(1, 0, "WIFI", "subWifi");
            var networkInfo2 = networkInfo_class.$new(0, 0, "MOBILE", "LTE");
            var netDetailedState = Java.use("android.net.NetworkInfo$DetailedState");
            networkInfo2.mIsAvailable.value = true;
            networkInfo2.setDetailedState(netDetailedState.CONNECTED.value, null, null);
            console.log('\t[!] return modified networkInfo');
            // console.log('\t[!] netInfo2: ' + networkInfo2);
            return networkInfo2;
        };

        var classx = Java.use("android.net.NetworkCapabilities");
        var hasTransport = classx.hasTransport;
        hasTransport.implementation = function (args) {
            console.log('[!] Hook NetworkCapabilities.hasTransport(i)');
            console.log("\t[!] Hook hasTransport(" + args + ")");
            var oldResult = hasTransport.call(this, args);
            console.log("\t[!] oldResult: " + oldResult);
            if (args == 0) {
                var newResult = true;
                console.log("\t[!] newResult: " + newResult);
                return newResult;
            } else {
                return false;
            }
            return false;
        };
    });
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

function NameValueTable_getStringForUser() //// same as - setupSystemPropertyHooks
{
    var NameValueCache = Java.use("android.provider.Settings$NameValueCache");
    var signature = NameValueCache.getStringForUser.overloads[0].toString()
    var setting_key_name = {
        "adb_enabled": "0",
        "development_settings_enabled": "0",
        "android_id": generateRandomAndroidId(),
        "auto_time": "1",
        "auto_time_zone": "1",
        "debug_app": null,
        //"http_proxy": null,
        "install_non_market_apps": "0",
        "http_proxy": "0",
        "bluetooth_name": "samsung",
        "wifi": "1",
        "wait_for_debugger": "0",
        "stay_on_while_plugged_in": "0",
        "wifi_on": "1",
        "mobile_data": "1",
    }

    NameValueCache.getStringForUser.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var keyName = args[1];
        let printStackFlag = false;

        if (keyName in setting_key_name) {
            var result = setting_key_name[keyName];
            if (keyName.indexOf("adb_enabled") != -1 || keyName.indexOf("development_settings_enabled") != -1) {
                printStackFlag = true;
            }
        }
        else {
            var result = this.getStringForUser.apply(this, args)
        }
        if (result == null)
            return result
        var info = {
            caller: "Setting",
            className: "android.provider.Settings",
            methodName: "getStringForUser",
            returnValue: result,
            arguments: keyName,
            signature: signature

        }

        send(info);
        if (printStackFlag) {
            stackTrace2();
        }

        return result

    }
}

function hookReactBridge() {
    var CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');

    // Hooking the overload with 'PendingJSCall' parameter
    CatalystInstanceImpl.callFunction.overload('com.facebook.react.bridge.CatalystInstanceImpl$PendingJSCall').implementation = function (pendingJSCall) {
        console.log('[Hook] callFunction(PendingJSCall) called');
        console.log('PendingJSCall: ' + pendingJSCall);
        return this.callFunction(pendingJSCall);
    };

    // Hooking the overload with 'String, String, NativeArray' parameters
    CatalystInstanceImpl.callFunction.overload('java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.NativeArray').implementation = function (module, method, args) {
        console.log('[Hook] callFunction(String, String, NativeArray) called');
        console.log('Module: ' + module);
        console.log('Method: ' + method);
        console.log('args: ' + args);
        return this.callFunction(module, method, args);
    };
}

function findClassInLoader(className) {
    var classFactory;
    var clzName = className;

    var classLoaders = Java.enumerateClassLoadersSync();
    for (var classLoader in classLoaders) {
        try {
            classLoaders[classLoader].findClass(clzName);
            classFactory = Java.ClassFactory.get(classLoaders[classLoader]);
            console.log('classLoader number: ' + classLoader + ', classLoader name: ' + classLoaders[classLoader]);
            break;
        } catch (e) {
            // console.log( e);*
            continue;
        }
    }

    var clz = classFactory.use(clzName);
    return clz
}

function pairip_license_bypass() {
    Java.perform(function () {
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
    });
}

function hook_jsonObj_writeTo(match) {
    var jsonObjCls = Java.use("org.json.JSONObject");

    jsonObjCls.writeTo.implementation = function (jsonStringer) {
        if (!jsonStringer) return this.writeTo(jsonStringer);

        var jsonStr = jsonStringer.toString();
        if (jsonStr && (!match || jsonStr.includes(match))) {
            console.log("Json: " + jsonStr);
            stackTrace2();
        }

        return this.writeTo(jsonStringer);
    };
}

function hook_ClipboardManager_getPrimaryClip() {
    Java.perform(function () {
        Java.use('android.content.ClipboardManager').getPrimaryClip.overload().implementation = function () {
            var clipVal = this.getPrimaryClip();
            send('Hooked fandroid.content.ClipboardManager.getPrimaryClip, value: ' + clipVal);
            stackTrace2();
            return clipVal;
        }
    });
}

function bypass_installReferrer() {
    // Install referrer
    const twoDaysAgo = Math.floor((Date.now() - 2 * 24 * 60 * 60 * 1000) / 1000);
    const twoDaysAgo_plus = twoDaysAgo + 78;

    hook_ReferrerDetails_getInstallReferrer("utm_source=facebook&utm_medium=social");
    hook_ReferrerDetails_getReferrerClickTimestampSeconds(twoDaysAgo);
    hook_ReferrerDetails_getInstallBeginTimestampSeconds(twoDaysAgo_plus);
}

function bypassKeyboardTimezone(country) {
    // *** Language and timezone
    const langArr = {
        Brazil: 'pt_BR',
        US: 'en_US',
        India: 'hi_IN',
        Turkey: 'tr_TR',
        Ukraine: 'uk_UA',
        Indonesia: 'id_ID',
        Thailand: 'th_TH',
        UAE: 'ar_AE',
        UK: 'en_GB',
        SaudiArabia: 'ar_SA',
        Austria: 'de_AT',
        Malaysia: 'ms_MY',
        Pakistan: 'ur_PK'
    };

    const timezoneArr = {
        Brazil: 'America/Sao_Paulo',
        US: 'America/New_York',
        India: 'Asia/Kolkata',
        Turkey: 'Europe/Istanbul',
        Ukraine: 'Europe/Kiev',
        Indonesia: 'Asia/Jakarta',
        Thailand: 'Asia/Bangkok',
        UAE: 'Asia/Dubai',
        UK: 'Europe/London',
        SaudiArabia: 'Asia/Riyadh',
        Austria: 'Europe/Vienna',
        Malaysia: 'Asia/Kuala_Lumpur',
        Pakistan: 'Asia/Karachi'
    };

    hook_InputMethodSubtype_getLanguageTag(langArr[country]);
    hook_TimeZone_getDefault(timezoneArr[country]);
    hook_TimeZone2_getDefault(timezoneArr[country]);

}

function HookSyncAdapter() {
    hook_account_init();
    hook_AccountManager_addAccountExplicitly();
    hook_ContentResolver_isSyncPending();
    hook_ContentResolver_requestSync();
    hook_ContentResolver_addPeriodicSync();
}

function hookURL(match) {
    if (match == null || match !== undefined) {
        match = 'zzzz';
    }

    hook_webview_loadUrl(match);
    hook_webview_loadUrl_2(match);
    hook_URL_openConnection(match);
    hook_URL_new(match);
}

function hookCipher() {
    hook_encryption_doFinal();
    hook_encryption_cipher();
    hook_encryption_aes();
}

function hookDCL() {
    hook_dexclassloader();
    hook_DexFile_loadClass();
    hook_InMemoryDexClassLoader();
}

function webViewHooks() {
    hook_webSettings_setJavaScriptEnabled();
    hook_webview_evaluateJavascript();
    hook_webview_addJavascriptInterface();
    hook_WebChromeClient_shouldOverrideUrlLoading();
    hook_webSettings_getUserAgentString();
}

function hook_InMemoryDexClassLoader() {
    Java.perform(function () {
        var IMdexclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        IMdexclassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (byteBuffer, classLoader) {
            send("InMemoryDexClassLoader constructor detected!");
            
            // Get the address and size of the ByteBuffer
            var bufferAddress = byteBuffer.array();
            var bufferSize = byteBuffer.capacity();

            // Create a file name for the dump
            var filename = 'dumped_dex_' + new Date().getTime() + '.dex';

            // Send a message with metadata and the binary payload
            send({
                'status': 'dumping',
                'filename': filename,
                'size': bufferSize,
                'loader': classLoader.toString()
            }, Memory.readByteArray(bufferAddress, bufferSize));

            // Call the original constructor to avoid crashing the application
            this.$init(byteBuffer, classLoader);
        }
    });
}

// Main
Java.perform(function () {
    send("start activating functions");

    // Activate methods here

    // ***** Cloaking Bypass *****

    pairip_license_bypass();
    updateBuildInfo(getBuildProfile("samsungS22")); // modifies the device's build information to mimic a different phone model
    anti_root();
    setupSystemPropertyHooks();
    hook_BatteryManager_getIntProperty(); // currently on - 89
    // SysPropsBypass(true); //system properties - need to select specific properties!
    // multipleUnpining();
    bypass_installReferrer();
    
    
    // ****** Ntwotk hooks *****

    wifiNetwork_hook(); //trick an app into thinking it's connected to a mobile network (LTE) even if it's not.
    hook_NetworkCapabilities_hasTransport(); // prevent an app from detecting if a VPN is active
    hook_NetworkInterface_getName(); // hide the presence of a VPN from a running Android application
    

    // ****** Specific cuntry/location ***********
    bypassKeyboardTimezone('india');
    //cellularHooks(true); // mMccMnc counryCode - need to uncomment the wanted country code. contains many send commands
    // *** Location - need to change the values!!!!!!!!!!!!!!!
    // hook_Location_getLatitude();
    // hook_Location_getLongitude();

    // **** frida ****
    //antiFridaBypass();
    
    

    // ****** duplicate - can be deleted
    //NameValueTable_getStringForUser(); //system properties same as  - setupSystemPropertyHooks

    // ***** Observe *****
    // hookURL();
    // hookCipher();
    // hookDCL();
    // hook_InMemoryDexClassLoader();
    
    // HookSyncAdapter();
    // hook_Activity_onCreate();

    // hook_ClipboardManager_getPrimaryClip();
    // hook_jsonObj_writeTo('deepseek.apk');
    // ok_http_ssl_cert_bypass();
    // SysPropsBypass(true);
    // hook_BluetoothAdapter_getBondedDevices();

    // hook_StringBuilder_append();
    // hook_StringBuilder_length();

    // *** Unity
    // waitForLoad('libil2cpp.so');
    // unity_printBridgeMsg();

    // hook_firestore_DocumentSnapshot_get('ak', 'asdfghjklzxcvbn');
    // hook_firestore_QueryDocumentSnapshot_getData("log", "0");

    // *** flock and fork
    // flock_hook(true);
    // fork_hook();

    



    // traceClasses();

    setTimeout(function () {
        send("Running delayed methods")
        // hook_packageManager_queryIntentActivities();
        // hook_hashMap_put();
        //traceClasses();
        //hook_PackageManager_getInstallerPackageName();
        hook_installTimeUpdate(72);
        // send(Java.enumerateLoadedClassesSync());
        // hook_native_file_open();

        // waitForLibLoading("libhermes.so");

        // hookReactBridge();
    }, 10);

    // hook_System_exit();

    // Files
    // hook_fileOutputStream_init();
    // hook_File_createNewFile();
    // hook_native_file_open();
    // hook_native_file_dlopen();
    // hook_fileDelete_native();
    // hook_native_file_stat();
    // hook_native_strstr();

    // hook_system_loadLibrary();
    // hook_system_load();

    // webViewHooks();

    // hook_getCookie();

    // hook_assetManager_open();

    // hook_base64_decode(false);
    // hook_java_base64_encodeToString(false);

    // hook_reflection();

    // hook_AdvertisingIdClient_Info_getId();
    // waitForDebugger();

    // hook_Activity_startActivity_1();
    // hook_Activity_startActivity_2();
    // hook_Context_startActivity_1();
    // hook_Context_startActivity_2();

    send("Script finished loading");
});