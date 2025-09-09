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

Java.perform(function () {
    setupSystemPropertyHooks();
});