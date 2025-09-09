Java.perform(function() {
    // JAVA HOOKS HERE
});


// --- Configuration ---
const packageName = "com.example.package";
const libName = "YOUR_LIB_NAME_HERE.so";
const functionName = "Java_com_example_package_MainActivity_functionName";


function hook() {
    // NATIVE HOOK HERE
    console.log(`[*] Searching for native functions in ${libName}...`);
    const funcPtr = Module.findExportByName(libName, functionName);
    
    if (funcPtr) {
        console.log(`[+] Found functionName() at ${funcPtr}. Setting up main Interceptor hook.`);
        
        Interceptor.attach(funcPtr, {
            onEnter(args) {
                console.log("\n[!!!] SUCCESS: Native function 'functionName()' was called!");
            },
            onLeave(retval) {
                retval.replace(0);
            }
        });
    } else {
        console.log(`[!] Failed to find native function ${functionName}.`);
    }
}

function hookLibraryLoad() {
    const dlopenExtAddr = Module.findExportByName(null, "android_dlopen_ext");
    if (dlopenExtAddr !== null) {
        Interceptor.attach(dlopenExtAddr, {
            onEnter(args) {
                var path = Memory.readCString(args[0]);
                if (path.includes(libName)) {
                    console.log(`[+] Found ${libName} at ${path}`);
                    this.shouldInitHooks = true;
                }
            },
            onLeave() {
                if (this.shouldInitHooks) {
                    console.log(`[+] Library ${libName} is now loaded!`);
                    hook()
                    this.shouldInitHooks = false;
                }
            }
        });
    } else {
        console.log(`[!] Unable to hook "android_dlopen_ext"`);
    }
}

hookLibraryLoad();