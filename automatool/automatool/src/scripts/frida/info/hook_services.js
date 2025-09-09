Java.perform(function () {
    var Context = Java.use("android.content.Context");
    var Service = Java.use("android.app.Service");

    // Hook startService
    Context.startService.overload("android.content.Intent").implementation = function (intent) {
        var comp = intent.getComponent();
        console.log("[Frida] startService: " + comp);
        return this.startService(intent);
    };

    // Hook startForegroundService (Android 8+)
    if (Context.startForegroundService) {
        Context.startForegroundService.overload("android.content.Intent").implementation = function (intent) {
            var comp = intent.getComponent();
            console.log("[Frida] startForegroundService: " + comp);
            return this.startForegroundService(intent);
        };
    }

    // Hook Service.onStartCommand
    Service.onStartCommand.implementation = function (intent, flags, startId) {
        console.log("[Frida] onStartCommand in: " + this.$className);
        return this.onStartCommand(intent, flags, startId);
    };
});
