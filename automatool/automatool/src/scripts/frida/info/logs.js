

function print_logs() {
    Java.perform(function() {
        var Log = Java.use("android.util.Log");

        Log.d.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(a, b, c) {
            console.log("[LOG] Log.d(" + a.toString() + ", " + b.toString() + ")");
            return this.d(a, b, c);
        };

        Log.v.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(a, b, c) {
            console.log("[LOG] Log.v(" + a.toString() + ", " + b.toString() + ")");
            return this.v(a, b, c);
        };
    
        Log.i.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(a, b, c) {
            console.log("[LOG] Log.i(" + a.toString() + ", " + b.toString() + ")");
            return this.i(a, b, c);
        };

        Log.e.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(a, b, c) {
            console.log("[LOG] Log.e(" + a.toString() + ", " + b.toString() + ")");
            return this.e(a, b, c);
        };

        Log.w.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function(a, b, c) {
            console.log("[LOG] Log.w(" + a.toString() + ", " + b.toString() + ")");
            return this.w(a, b, c);
        };

        Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
            console.log("[LOG] Log.d(" + a.toString() + ", " + b.toString() + ")");
            return this.d(a, b);
        };

        Log.v.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
            console.log("[LOG] Log.v(" + a.toString() + ", " + b.toString() + ")");
            return this.v(a, b);
        };
    
        Log.i.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
            console.log("[LOG] Log.i(" + a.toString() + ", " + b.toString() + ")");
            return this.i(a, b);
        };
        Log.e.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
            console.log("[LOG] Log.e(" + a.toString() + ", " + b.toString() + ")");
            return this.e(a, b);
        };
        Log.w.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
            console.log("[LOG] Log.w(" + a.toString() + ", " + b.toString() + ")");
            return this.w(a, b);
        };
    });
}


Java.perform(function() {
    print_logs();
});