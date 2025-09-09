
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

Java.perform(function () {
    VPNHook();
});