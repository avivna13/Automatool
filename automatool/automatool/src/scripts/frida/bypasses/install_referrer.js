function installReferrerHook(){
    let com_android_installreferrer_api_ReferrerDetails = Java.use("com.android.installreferrer.api.ReferrerDetails");
    com_android_installreferrer_api_ReferrerDetails.$init.overload("android.os.Bundle").implementation = function (arg0) {
        console.log(`[+] Hooked com.android.installreferrer.api.ReferrerDetails.<init>: arg0=${arg0}`);
        this["$init"](arg0);
        let installReferrer = "utm_source=google-play&utm_medium=non-organic"; // This is the important part.

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

Java.perform(function () {
    installReferrerHook();
});
