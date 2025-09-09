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

Java.perform(function(){
    dex_loading_tracer();
    in_memory_dex_loading_tracer();
})