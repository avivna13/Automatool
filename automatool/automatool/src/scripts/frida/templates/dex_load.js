Java.perform(() => {
    // --- All relevant loaders ---
    const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    const DexClassLoader     = Java.use("dalvik.system.DexClassLoader");
    const PathClassLoader    = Java.use("dalvik.system.PathClassLoader");

    /**
     * Install loadClass() hooks on the given loader class.
     * When a new class is loaded, call hookMethodsFromClass().
     */
    function hookLoader(loaderClazz) {
        // loadClass(String)
        loaderClazz.loadClass.overload("java.lang.String")
        .implementation = function (className) {
            const cls = this.loadClass(className);
            hookMethodsFromClass(className, cls);
            return cls;
        };

        // loadClass(String, boolean)
        loaderClazz.loadClass.overload("java.lang.String", "boolean")
        .implementation = function (className, resolve) {
            const cls = this.loadClass(className, resolve);
            hookMethodsFromClass(className, cls);
            return cls;
        };
    }

    /**
     * Hook interesting methods from a loaded class *using the
     * ClassLoader that actually created it*. Using the factory
     * tied to that loader is essential—if you fall back to
     * Java.use() (default loader), the class may be invisible.
     */
    function hookMethodsFromClass(className, loadedClass) {
		/***************** CHANGE TARGET CLASS *****************/
		const TARGET_CLASS = "com.brick.bre.Brick";
		/*******************************************************/
		    
    if (className !== TARGET_CLASS) { return; }

    const classLoader = loadedClass.getClassLoader();
    const factory     = Java.ClassFactory.get(classLoader);  // 👈 non-negotiable!

    const Target = factory.use(TARGET_CLASS);
 
		/***************** EXAMPLE HOOK *****************/
      Target["$init"].implementation = function (activity) {
          console.log(`Brick.$init is called: activity=${activity}`);
          this["$init"](activity);
      };		
    /************************************************/
    }

    // Hook every loader type we care about.
    [BaseDexClassLoader, DexClassLoader, PathClassLoader].forEach(hookLoader);

    /**
     * Malware sometimes calls ClassLoader.loadClass() via reflection:
     *   Method m = loader.getClass().getMethod("loadClass", String.class);
     *   m.invoke(loader, "evil.payload.Foo");
     * Hook Method.invoke() so we still see and handle those cases.
     */
    const Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function (receiver, ...args) {
        try {
            if (this.getName() === "loadClass" && args.length > 0) {
                console.log(`[reflect] loadClass via reflection: ${args[0]}`);
            }
        } catch (_) { /* ignore */ }
        return this.invoke(receiver, ...args);
    };
});
