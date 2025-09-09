import xml.etree.ElementTree as ET
from .utils import (
    str2Bool,
    getResourceTypeName,
    formatResource
)
from itertools import product
from collections import namedtuple


class Parser:

    def __init__(self, path):
        self.namespaces = dict([node for _, node in ET.iterparse(path, events=['start-ns'])])
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()
        self.apk = None

    def _getattr(self, elm, attr):
        """
        A helper function to get an attribute.
        Attributes might have a prefix like "@android:"
        If the attribute is a resource (starts with @) the result is formatted in a more intelligible manner.
        """
        if ":" in attr:
            prefix, uri = attr.split(":", 1)
            attr = f"{{{self.namespaces[prefix]}}}{uri}"
        res = elm.attrib.get(attr)
        if res and res.startswith("@"):
            # resource
            path, name = getResourceTypeName(res)
            res = formatResource(path, name)
        return res

    def getApkInfo(self):
        """
        List useful information found in the <manifest> element.
        https://developer.android.com/guide/topics/manifest/manifest-element
        The information is package, version code and version name.
        """
        # use a namedtuple for more readable access to important attributes
        Info = namedtuple("Info", "package versionCode versionName")
        package = self._getattr(self.root, "package")
        versionCode = self._getattr(self.root, "android:versionCode")
        versionName = self._getattr(self.root, "android:versionName")
        return Info(package, versionCode, versionName)

    def usesLibrary(self):
        """
        Parses the libraries used by the application.
        https://developer.android.com/guide/topics/manifest/uses-library-element
        """
        UsesLibrary = namedtuple("UsesLibrary", "name required")
        res = []
        for e in self.root.findall("application/uses-library"):
            name = self._getattr(e, "android:name")
            required = str2Bool(self._getattr(e, "android:required"))
            # Default is true for android:required property
            if required is None:
                required = True
            res.append(UsesLibrary(name, required))
        return res

    def usesNativeLibrary(self):
        """
        Parses the native libraries used by the application.
        https://developer.android.com/guide/topics/manifest/uses-native-library-element
        """
        UsesNativeLibrary = namedtuple("UsesNativeLibrary", "name required")
        res = []
        for e in self.root.findall("application/uses-native-library"):
            name = self._getattr(e, "android:name")
            required = str2Bool(self._getattr(e, "android:required"))
            # Default is true for android:required property
            if required is None:
                required = True
            res.append(UsesNativeLibrary(name, required))
        return res

    def usesFeatures(self):
        """
        Parses the hardware or software features used by the application.
        https://developer.android.com/guide/topics/manifest/uses-feature-element
        """
        UsesFeature = namedtuple("UsesFeature", "name required")
        res = []
        for e in self.root.findall("uses-feature"):
            name = self._getattr(e, "android:name")
            required = str2Bool(self._getattr(e, "android:required"))
            # Default is true for android:required property
            if required is None:
                required = True
            res.append(UsesFeature(name, required))
        return res

    def requiredPermissions(self):
        """
        Lists all the permissions requested by the application.
        https://developer.android.com/guide/topics/manifest/uses-permission-element
        """
        return [self._getattr(perm, "android:name") for perm in self.root.findall('uses-permission')]

    def allowBackup(self):
        """
        Indicates if the application is allowing backups.
        https://developer.android.com/guide/topics/manifest/application-element#allowbackup
        """
        allowBackup = str2Bool(self._getattr(self.root.find("application"), "android:allowBackup"))
        # Default value is True
        if allowBackup is None:
            allowBackup = True
        return allowBackup

    def backupAgent(self):
        """
        Returns the configured backup agent or None.
        https://developer.android.com/guide/topics/manifest/application-element#agent
        """
        return self._getattr(self.root.find("application"), "android:backupAgent")

    def debuggable(self):
        """
        Indicates if the application is debuggable.
        https://developer.android.com/guide/topics/manifest/application-element#debug
        """
        debuggable = str2Bool(self._getattr(self.root.find("application"), "android:debuggable"))
        # Default value is False
        if debuggable is None:
            debuggable = False
        return debuggable

    def usesCleartextTraffic(self):
        """
        Indicates if the application allows clear text traffic.
        https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic
        """
        return str2Bool(self._getattr(self.root.find("application"), "android:usesCleartextTraffic"))

    def customPermissions(self):
        """
        Lists all the custom permissions defined by the application.
        https://developer.android.com/guide/topics/manifest/permission-element
        """
        CustomPerm = namedtuple("CustomPerm", "name protectionLevel")
        res = []
        for perm in self.root.findall('permission'):
            name = self._getattr(perm, "android:name")
            protectionLevel = self._getattr(perm, "android:protectionLevel") or "normal"
            res.append(CustomPerm(name, protectionLevel))
        return res

    def exportedComponents(self, component):
        """
        Lists all the exported components of a given type (activity, provider, ...).

        For all components, android:exported is false since Android 4.2. However, 
        if this component specifies an intent filter, android:exported is automatically set to True
        From Android 12, it's mandatory to specify android:exported property if a component
        contains an intent filter (False or True) -> to avoid error. Otherwise, a runtime error will be delivered.
        
        BLOG ARTICLE : https://medium.com/androiddevelopers/lets-be-explicit-about-our-intent-filters-c5dbe2dbdce0
        An important change is coming to Android 12 that improves both app and platform security. This change affects
        all apps that target Android 12. Activities, services, and broadcast receivers with declared intent-filters now
        must explicitly declare whether they should be exported or not. Prior to Android 12, components (activities,
        services, and broadcast receivers only) with an intent-filter declared were automatically exported
        """
        # check if there is android:exported property set to True (no matter intent filter)
        exported_component = {self._getattr(e, "android:name") for e in
                              self.root.findall(f'application/{component}[@android:exported="true"]',
                                                namespaces=self.namespaces)}
        # check if there is an intent filter in component tag
        intent_component = {self._getattr(e, "android:name") for e in
                            self.root.findall(f'application/{component}/intent-filter/..', namespaces=self.namespaces)}
        # check if there is android:exported property set to False (no matter intent filter)
        unexported_component = {self._getattr(e, "android:name") for e in
                                self.root.findall(f'application/{component}[@android:exported="false"]',
                                                  namespaces=self.namespaces)}
        # update components (if there is android:exported to False and intent-filter, component is not exported)
        exported_component.update(intent_component - unexported_component)
        return list(exported_component)

    def componentStats(self, component):
        """
        Counts the number of components of a given type (activity, provider, ...).
        """
        return len(self.root.findall(f'application/{component}'))

    def exportedComponentStats(self, component):
        """
        Counts the number of exported components of a given type (activity, provider, ...).
        """
        return len(self.exportedComponents(component))

    def fullBackupContent(self):
        """
        Returns the configured backup rules file for android <= 11 or None.
        https://developer.android.com/guide/topics/manifest/application-element#fullBackupContent
        """
        return self._getattr(self.root.find("application"), "android:fullBackupContent")

    def dataExtractionRules(self):
        """
        Returns the configured backup rules file for android >= 12 or None.
        https://developer.android.com/guide/topics/manifest/application-element#dataExtractionRules
        """
        return self._getattr(self.root.find("application"), "android:dataExtractionRules")

    def networkSecurityConfig(self):
        """
        Returns the network security configuration file or None.
        https://developer.android.com/guide/topics/manifest/application-element#networkSecurityConfig
        """
        return self._getattr(self.root.find("application"), "android:networkSecurityConfig")

    def getSdkVersion(self):
        """
        Returns the minimal and maximal SDK versions defined in the manifest.
        https://developer.android.com/guide/topics/manifest/uses-sdk-element
        """
        usesSdk = self.root.find("uses-sdk")
        # if not defined return 0
        min_level = 0
        target_level = 0
        max_level = 0
        if usesSdk is not None:
            # if uses-sdk exists but the minSdkVersion is not set, the default value is 1
            min_level = int(self._getattr(usesSdk, "android:minSdkVersion") or 1)
            # if uses-sdk exists but the targetSdkVersion is not set, the default value is the same as minSdkVersion
            target_level = int(self._getattr(usesSdk, "android:targetSdkVersion") or min_level)
            # if max_level does not exist return 0
            max_level = int(self._getattr(usesSdk, "android:maxSdkVersion") or 0)
        return min_level, target_level, max_level

    def getExportedComponentPermission(self, componentType):
        """
        Lists all exported components of a given type (activity, provider, ...) and their permissions.
        https://developer.android.com/guide/topics/manifest/<componentType>-element

        For ACTIVITY, SERVICE, RECEIVER: android:permission
        For PROVIDER: android:permission, android:grantUriPermissions, android:readPermission, android:writePermission

        android:permission :
        The name of a permission that clients must have to read or write the content provider's data.
        This attribute is a convenient way of setting a single permission for both reading and writing.
        However, the readPermission, writePermission, and grantUriPermissions (False by default) attributes
        take precedence over this one.
        """

        # use a namedtuple for more readable access to important attributes
        ExportedComponents = namedtuple("ExportedComponents",
                                        "componentName componentType permission readPermission "
                                        "writePermission grantUriPermissions")
        res = []
        for name in self.exportedComponents(componentType):
            component = self.root.find(f'application/{componentType}[@android:name="{name}"]',
                                       namespaces=self.namespaces)
            permission = self._getattr(component, "android:permission")
            readPermission, writePermission, grantUriPermissions = None, None, None
            if componentType == "provider":
                # only providers have those attributes
                readPermission = self._getattr(component, "android:readPermission")
                writePermission = self._getattr(component, "android:writePermission")
                grantUriPermissions = str2Bool(self._getattr(component, "android:grantUriPermissions"))
            res.append(ExportedComponents(name, componentType, permission, readPermission, writePermission,
                                          grantUriPermissions))
        return res

    def getUnexportedProviders(self):
        """
        Lists unexported providers with grantUriPermission set to True.
        Dangerous because if the app uses getIntent().getParcelableExtra("extra_intent"), this
        can grant access to these unexported provider.
        https://blog.oversecured.com/Android-Access-to-app-protected-components/
        https://snyk.io/blog/exploring-android-intent-based-security-vulnerabilities-google-play/
        """
        return {self._getattr(e, "android:name") for e in self.root.findall(
            f'application/provider[@android:grantUriPermissions="true"][@android:exported="false"]',
            namespaces=self.namespaces)}

    def getIntentFilterExportedComponents(self):
        """
        Returns a tuple (componentName, componentType) for each exported component having
        one or more intent_filter(s) (android:exported is true or none)
        """
        all_intent = {(self._getattr(e, "android:name"), e.tag) for e in
                      self.root.findall(f'application/*/intent-filter/..')}
        not_exported = {(self._getattr(e, "android:name"), e.tag) for e in
                        self.root.findall(f'application/*[@android:exported="false"]/intent-filter/..',
                                          namespaces=self.namespaces)}
        return all_intent - not_exported

    def getIntentFilters(self, compname):
        """
        Returns a list containing intent_filters information (action, category, data_uris, mimetypes)
        from an Element with given name.
        """
        # get intent-filter element from a Element with given name
        intents = self.root.findall(f"application/*[@android:name=\"{compname}\"]/intent-filter",
                                    namespaces=self.namespaces)
        res = []
        # each intent on a separated line
        for e in intents:
            # an intent can have multiple actions
            actions = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("action")]
            actions = "\n".join(actions)
            # an intent can have multiple categories
            categories = [self._getattr(e, "android:name").split(".")[-1] for e in e.findall("category")]
            categories = "\n".join(categories)
            mimeType = {self._getattr(e, "android:mimeType") for e in e.findall("data")} - {None} or {""}
            mimetypes = "\n".join(mimeType)

            # Compute all the merged combinations of data attributes
            # https://developer.android.com/guide/topics/manifest/data-element
            uris = self._getIntentFiltersUrisInfo(e, len(mimeType) > 1)
            uris = "\n".join(uris)

            res.append([actions, categories, uris, mimetypes])

        return res

    def _getIntentFiltersUrisInfo(self, intent, hasMimeType):
        """
        Lists all the URIs of the given <intent-filter> element.

        https://developer.android.com/training/app-links/verify-android-applinks#multi-host
        All <data> elements in the same intent filter are merged together to account for all variations of their
        combined attributes. For example, the first intent filter above includes a <data> element that only declares
        the HTTPS scheme. But it is combined with the other <data> element so that the intent filter supports both
        http://www.example.com and https://www.example.com. As such, you must create separate intent filters when
        you want to define specific combinations of URI schemes and domains.
        """
        datas = intent.findall("data")
        # recover all the possible attributes
        schemes = {self._getattr(e, "android:scheme") for e in datas} - {None}
        schemes = {f"{e}://" for e in schemes} or {""}
        # https://developer.android.com/guide/topics/manifest/data-element
        if hasMimeType and schemes == {""}:
            schemes = {"content://", "file://"}

        hosts = {self._getattr(e, "android:host") for e in datas} - {None} or {""}
        port = {self._getattr(e, "android:port") for e in datas} - {None}
        port = {f":{e}" for e in port} or {""}

        # path, pathPattern and pathPrefix have the same role
        path = {self._getattr(e, "android:path") for e in datas} - {None}
        pathPattern = {self._getattr(e, "android:pathPattern") for e in datas} - {None}
        pathPrefix = {self._getattr(e, "android:pathPrefix") for e in datas} - {None}
        pathPrefix = {f"{e}/.*" for e in pathPrefix} or {""}  # respect syntax of pathPattern
        # put them in the same set
        path.update(pathPrefix)
        path.update(pathPattern)

        # https://developer.android.com/guide/topics/manifest/data-element
        if schemes == {""}:
            return []

        if hosts == {""}:
            return schemes

        # Compute all the merged combinations of data attributes
        # https://developer.android.com/guide/topics/manifest/data-element
        return ["".join(uri) for uri in product(schemes, hosts, port, path)]

    def getUniversalLinks(self):
        """
        Returns a list containing Universal links (deep links and app links) information
        (component_name, type, autoverify, data_uris, hosts) from an Element with given name.

        https://developer.android.com/training/app-links/deep-linking
        Universal links are intent filters having a VIEW action and a BROWSABLE category.
        """
        # do not keep the tag
        exported_components = self.getIntentFilterExportedComponents()
        # use a namedtuple for more readable access to important attributes
        UniversalLink = namedtuple("UniversalLink", "name tag autoVerify uris hosts")
        deepLinks = []
        for compname, tag in exported_components:
            # deep links must have ACTION_VIEW
            intents = self.root.findall(f'application/*[@android:name=\"{compname}\"]/intent-filter/'
                                        f'action[@android:name="android.intent.action.VIEW"]/..',
                                        namespaces=self.namespaces)
            for i in intents:
                # deep links must have category BROWSABLE
                if i.find('category[@android:name="android.intent.category.BROWSABLE"]',
                          namespaces=self.namespaces) is not None:
                    mimeType = {self._getattr(e, "android:mimeType") for e in i.findall("data")}
                    uris = self._getIntentFiltersUrisInfo(i, len(mimeType) > 1)
                    # add additional info to check if a deeplink is actually an app link
                    hosts = {self._getattr(e, "android:host") for e in i.findall("data")} - {None} or {""}
                    autoVerify = str2Bool(self._getattr(i, "android:autoVerify"))
                    deepLinks.append(UniversalLink(compname, tag, autoVerify, uris, hosts))

        return deepLinks

    def getFullBackupContentRules(self):
        # will be overridden in the APKParser class
        return []

    def getDataExtractionRulesContent(self):
        # will be overridden in the APKParser class
        return None

    def hasFile(self, path):
        # will be overridden in the APKParser class
        return False

    def searchInStrings(self, pattern):
        # will be overridden in the APKParser class
        return []

    def getNetworkSecurityConfigFile(self):
        # will be overridden in the APKParser class
        return None

    def fullBackupOnly(self):
        """
        Checks whether to use Auto Backup on devices where it is available
        https://developer.android.com/guide/topics/manifest/application-element#fullBackupOnly
        """
        fullBackupOnly = str2Bool(self._getattr(self.root.find("application"), "android:fullBackupOnly"))
        # Default value is False
        if fullBackupOnly is None:
            fullBackupOnly = False
        return fullBackupOnly

    def getSingleTaskActivities(self):
        """
        Returns a list of activities whose launch mode is set to singleTask and taskAffinity to ""
        """
        singleTask = self.root.findall(f'application/activity[@android:launchMode="singleTask"]',
                                                    namespaces=self.namespaces)
        
        # In some APK it is the enum value only singleTask=2
        singleTask += self.root.findall(f'application/activity[@android:launchMode="2"]',
                                                    namespaces=self.namespaces)
        
        singleTask_with_task_affinity = self.root.findall(f'application/activity[@android:taskAffinity=""]',
                                                    namespaces=self.namespaces)
        
        single_task_activities = [self._getattr(e, "android:name").split(".")[-1] for e in
                                  list(singleTask) if e not in singleTask_with_task_affinity]
        
        return single_task_activities

    def getComponentCustomPerms(self, component):
        """
        Lists all components and their associated custom permission
        The list is returned as a namedtuple made of component's name and permission
        """
        CustomPermsComponent = namedtuple("CustomPermsComponent", "name permission")
        res = []
        for e in self.root.findall(f"application/{component}"):
            name = self._getattr(e, "android:name")
            permission = self._getattr(e, "android:permission")
            # only get custom permission(s) (android:permission prefix is only used for builtin ones)
            if permission is not None and not permission.startswith("android.permission"):
                res.append(CustomPermsComponent(name, permission))
        return res

    def getCustomPermsUsageError(self, component):
        """
        Lists all components which misuse custom permission (android:uses-permission instead of android:permission)
        """
        return [self._getattr(e, "android:name") for e in
                self.root.findall(f'application/{component}[@android:uses-permission]',
                                  namespaces=self.namespaces)
                if not self._getattr(e, "android:uses-permission").startswith("android.permission")]
    
    def isGlobalTaskAffinity(self):
        """
        Returns the value of taskAffinity in application tag.
        """
        return self._getattr(self.root.find("application"), "android:taskAffinity")

    def getAccessibilityServices(self):
        """
        Detects accessibility services in the manifest.
        
        Accessibility services are identified by:
        - Service component with android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
        - Intent filter with action="android.accessibilityservice.AccessibilityService"
        
        Returns:
            List[AccessibilityService]: List of accessibility service information
        """
        AccessibilityService = namedtuple("AccessibilityService", 
                                        "name permission exported enabled")
        
        # Find services with BIND_ACCESSIBILITY_SERVICE permission
        accessibility_services = []
        for service in self.root.findall('application/service[@android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"]', 
                                       namespaces=self.namespaces):
            name = self._getattr(service, "android:name")
            permission = self._getattr(service, "android:permission") 
            exported = str2Bool(self._getattr(service, "android:exported"))
            enabled = str2Bool(self._getattr(service, "android:enabled"))
            
            # Verify it has accessibility intent filter
            intent_filter = service.find('intent-filter/action[@android:name="android.accessibilityservice.AccessibilityService"]',
                                       namespaces=self.namespaces)
            
            if intent_filter is not None:
                accessibility_services.append(AccessibilityService(name, permission, exported, enabled))
        
        return accessibility_services

    def getContactDirectoryProviders(self):
        """
        Detects content providers that may expose contact directory information.
        
        Identifies providers by:
        - Authority containing "contacts" or "directory"
        - READ_CONTACTS or WRITE_CONTACTS permissions
        - Meta-data indicating contact directory support
        
        Returns:
            List[ContactDirectoryProvider]: List of contact directory providers
        """
        ContactDirectoryProvider = namedtuple("ContactDirectoryProvider", 
                                            "name authority permission readPermission writePermission "
                                            "exported grantUriPermissions contactsRelated")
        
        contact_providers = []
        
        # Get all providers
        for provider in self.root.findall('application/provider', namespaces=self.namespaces):
            name = self._getattr(provider, "android:name")
            authority = self._getattr(provider, "android:authorities")
            permission = self._getattr(provider, "android:permission")
            readPermission = self._getattr(provider, "android:readPermission") 
            writePermission = self._getattr(provider, "android:writePermission")
            exported = str2Bool(self._getattr(provider, "android:exported"))
            grantUriPermissions = str2Bool(self._getattr(provider, "android:grantUriPermissions"))
            
            # Check if this provider is contacts-related
            contacts_related = self._isContactsRelatedProvider(provider, authority, permission, 
                                                             readPermission, writePermission)
            
            if contacts_related:
                contact_providers.append(ContactDirectoryProvider(
                    name, authority, permission, readPermission, writePermission,
                    exported, grantUriPermissions, contacts_related
                ))
        
        return contact_providers

    def _isContactsRelatedProvider(self, provider, authority, permission, readPermission, writePermission):
        """
        Helper method to determine if a provider is contacts-related.
        
        Returns:
            str: Reason why it's considered contacts-related, or None if not
        """
        if authority:
            authority_lower = authority.lower()
            if any(keyword in authority_lower for keyword in ['contacts', 'directory', 'people', 'phonebook']):
                return f"Authority contains contacts-related keyword: {authority}"
        
        # Check permissions
        contact_permissions = [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS'
        ]
        
        for perm in [permission, readPermission, writePermission]:
            if perm in contact_permissions:
                return f"Uses contacts permission: {perm}"
        
        # Check meta-data for contacts directory indicators
        for meta_data in provider.findall('meta-data', namespaces=self.namespaces):
            meta_name = self._getattr(meta_data, "android:name")
            if meta_name and any(keyword in meta_name.lower() for keyword in ['contacts', 'directory']):
                return f"Meta-data indicates contacts: {meta_name}"
        
        return None

    def getNotificationListenerServices(self):
        """
        Detects notification listener services in the manifest.
        
        Notification listener services are identified by:
        - Service component with android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        - Intent filter with action="android.service.notification.NotificationListenerService"
        
        Returns:
            List[NotificationListenerService]: List of notification listener service information
        """
        NotificationListenerService = namedtuple("NotificationListenerService", 
                                                "name permission exported enabled")
        
        # Find services with BIND_NOTIFICATION_LISTENER_SERVICE permission
        notification_services = []
        for service in self.root.findall('application/service[@android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"]', 
                                       namespaces=self.namespaces):
            name = self._getattr(service, "android:name")
            permission = self._getattr(service, "android:permission") 
            exported = str2Bool(self._getattr(service, "android:exported"))
            enabled = str2Bool(self._getattr(service, "android:enabled"))
            
            # Verify it has notification listener intent filter
            intent_filter = service.find('intent-filter/action[@android:name="android.service.notification.NotificationListenerService"]',
                                       namespaces=self.namespaces)
            
            if intent_filter is not None:
                notification_services.append(NotificationListenerService(name, permission, exported, enabled))
        
        return notification_services