
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

Java.perform(function () {
    bypassNetworkConnectionChecks(true);
});