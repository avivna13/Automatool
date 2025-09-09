
function bypassLiscenceCheck() {
    let ResponseValidator = Java.use('com.pairip.licensecheck.ResponseValidator');
        ResponseValidator.validateResponse.overload("android.os.Bundle", "java.lang.String").implementation = function(arg0, arg1) {
            console.log(`[->] validateResponse: arg0=${arg0}, arg1=${arg1}`);
            console.log("Bypassing validateResponse by returning immideately...");
            return
        };

    let LicenseClient = Java.use('com.pairip.licensecheck.LicenseClient');
        LicenseClient.processResponse.overload("int", "android.os.Bundle").implementation = function(arg0, arg1) {
            console.log(`[->] processResponse: arg0=${arg0}, arg1=${arg1}`);
            console.log(`Bypassing processResponse by changing [arg0] from ${arg0} to 0`);
            this['processResponse'](0, arg1);
        };
}



// Bypass licensecheck done by Google's com.pairip.licensecheck.
Java.perform(function() {
    bypassLiscenceCheck();
});