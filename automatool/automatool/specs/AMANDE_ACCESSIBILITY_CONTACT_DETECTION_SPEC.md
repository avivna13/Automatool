# AMAnDe Enhancement Specification: Accessibility Services & Contact Directory Content Providers Detection

## Overview

This specification outlines the enhancement of AMAnDe (Android Manifest Anomaly Detector) to detect two additional security-relevant components:

1. **Accessibility Services** - Services that can access and interact with UI elements across the entire system
2. **Content Providers with Contact Directories** - Providers that expose contact-related data which could be privacy-sensitive

## Current AMAnDe Architecture Analysis

Based on the codebase analysis:

- **Main Entry Point**: `main.py` orchestrates the analysis
- **Parser Layer**: `parser.py` handles XML parsing and component extraction
- **Analysis Layer**: `analyzer.py` performs security analysis and reporting
- **Output**: Console logging + optional JSON export

The existing pattern follows:
1. Parser methods extract component data from AndroidManifest.xml
2. Analyzer methods perform security analysis and generate reports
3. Results are logged and optionally exported to JSON

## Feature Specification

### 1. Accessibility Services Detection

#### 1.1 Parser Enhancement (`parser.py`)

**New Method**: `getAccessibilityServices()`

```python
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
        intent_filter = service.find('intent-filter/action[@android:name="android.accessibilityservice.AccessibilityService"]/..',
                                   namespaces=self.namespaces)
        
        if intent_filter is not None:
            accessibility_services.append(AccessibilityService(name, permission, exported, enabled))
    
    return accessibility_services
```

#### 1.2 Analyzer Enhancement (`analyzer.py`)

**New Method**: `analyzeAccessibilityServices()`

```python
def analyzeAccessibilityServices(self):
    """
    Analyzes accessibility services and their security implications.
    
    Security concerns:
    - Accessibility services have broad system access
    - Can read screen content, inject input events
    - Often used by malware for overlay attacks, credential theft
    """
    printTestInfo("Analyzing Accessibility Services")
    
    accessibility_services = self.parser.getAccessibilityServices()
    jres = []
    
    if len(accessibility_services) == 0:
        self.logger.info("No accessibility services found")
        self.json_result["Accessibility Services"] = jres
        return
    
    for service in accessibility_services:
        service_name = service.name.split(".")[-1]
        jres.append({
            "name": service_name,
            "full_name": service.name,
            "permission": service.permission,
            "exported": service.exported,
            "enabled": service.enabled
        })
        
        # Security warnings
        self.logger.warning(f'Accessibility service found: {service_name}')
        
        if service.exported:
            self.logger.critical(f'Accessibility service {service_name} is exported - HIGH RISK')
        
        if service.enabled is not False:  # None or True
            self.logger.warning(f'Accessibility service {service_name} is enabled by default')
    
    self.json_result["Accessibility Services"] = jres
    
    # Summary warning
    if len(accessibility_services) > 0:
        self.logger.warning(f'Found {len(accessibility_services)} accessibility service(s). '
                           f'These services have extensive system access and should be carefully reviewed.')
```

### 2. Content Providers with Contact Directories Detection

#### 2.1 Parser Enhancement (`parser.py`)

**New Method**: `getContactDirectoryProviders()`

```python
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
```

#### 2.2 Analyzer Enhancement (`analyzer.py`)

**New Method**: `analyzeContactDirectoryProviders()`

```python
def analyzeContactDirectoryProviders(self):
    """
    Analyzes content providers that may expose contact directory information.
    
    Security concerns:
    - Contact data is highly sensitive personal information
    - Exported providers without proper permissions can leak contacts
    - Directory providers may expose organization contact lists
    """
    printTestInfo("Analyzing Contact Directory Content Providers")
    
    contact_providers = self.parser.getContactDirectoryProviders()
    jres = []
    
    if len(contact_providers) == 0:
        self.logger.info("No contact directory providers found")
        self.json_result["Contact Directory Providers"] = jres
        return
    
    for provider in contact_providers:
        provider_name = provider.name.split(".")[-1]
        jres.append({
            "name": provider_name,
            "full_name": provider.name,
            "authority": provider.authority,
            "permission": provider.permission,
            "read_permission": provider.readPermission,
            "write_permission": provider.writePermission,
            "exported": provider.exported,
            "grant_uri_permissions": provider.grantUriPermissions,
            "contacts_related_reason": provider.contactsRelated
        })
        
        # Security analysis
        self.logger.warning(f'Contact directory provider found: {provider_name}')
        self.logger.info(f'  Authority: {provider.authority}')
        self.logger.info(f'  Reason: {provider.contactsRelated}')
        
        # Security warnings
        if provider.exported and not any([provider.permission, provider.readPermission, provider.writePermission]):
            self.logger.critical(f'Contact provider {provider_name} is exported without permissions - HIGH RISK')
        
        if provider.grantUriPermissions:
            self.logger.warning(f'Contact provider {provider_name} grants URI permissions')
    
    self.json_result["Contact Directory Providers"] = jres
    
    # Summary
    if len(contact_providers) > 0:
        self.logger.warning(f'Found {len(contact_providers)} contact directory provider(s). '
                           f'Ensure proper access controls are in place.')
```

### 3. Integration with Main Analysis Flow

#### 3.1 Update `analyzer.py` - `runAllTests()` method

Add the new analysis methods to the main analysis flow:

```python
def runAllTests(self):
    print(colored(f"Analysis of {self.args.path}", "magenta", attrs=["bold"]))
    
    self.showApkInfo()
    
    self.analyzeRequiredPerms()
    self.analyzeCustomPerms()
    self.analyzeBackupFeatures()
    self.isDebuggable()
    self.getNetworkConfigFile()
    self.isCleartextTrafficAllowed()
    self.getExportedComponents()
    self.analyzeIntentFilters()
    self.analyzeExportedComponent()
    self.analyzeUnexportedProviders()
    
    # NEW: Add accessibility services and contact providers analysis
    self.analyzeAccessibilityServices()
    self.analyzeContactDirectoryProviders()
    
    self.checkForFirebaseURL()
    self.analyzeCustomPermsUsage()
    self.analyzeActivitiesLaunchMode()

    if self.args.json is not None:
        with open(self.args.json, "w") as f:
            json.dump(self.json_result, f)
            f.write("\n")
        self.logger.info(colored(f"\nJSON output written to {self.args.json}.", "green"))
```

## Implementation Approach

### Phase 1: Parser Methods (Simplest Implementation)
1. Add `getAccessibilityServices()` method to `parser.py`
2. Add `getContactDirectoryProviders()` and helper method to `parser.py`
3. Test parser methods with sample manifests

### Phase 2: Analyzer Methods
1. Add `analyzeAccessibilityServices()` method to `analyzer.py`
2. Add `analyzeContactDirectoryProviders()` method to `analyzer.py`
3. Test analysis output and logging

### Phase 3: Integration
1. Update `runAllTests()` to call new analysis methods
2. Test complete integration
3. Verify JSON output format

## Testing Strategy

### Test Cases

1. **Accessibility Services**:
   - Manifest with legitimate accessibility service
   - Manifest with exported accessibility service (security risk)
   - Manifest with no accessibility services

2. **Contact Directory Providers**:
   - Provider with "contacts" in authority
   - Provider with READ_CONTACTS permission
   - Provider with contacts-related meta-data
   - Exported provider without permissions (security risk)
   - No contact-related providers

### Sample Test Manifests

Create test manifests in `examples/` directory with various combinations of these components.

## Security Benefits

1. **Accessibility Services Detection**:
   - Identifies services with broad system access
   - Flags exported accessibility services (major security risk)
   - Helps detect potential malware using accessibility for overlay attacks

2. **Contact Directory Providers Detection**:
   - Identifies providers exposing sensitive contact information
   - Flags inadequate permission controls
   - Helps prevent contact data leakage

## Output Examples

### Console Output
```
[INFO] Analyzing Accessibility Services
[WARNING] Accessibility service found: CustomAccessibilityService  
[CRITICAL] Accessibility service CustomAccessibilityService is exported - HIGH RISK
[WARNING] Found 1 accessibility service(s). These services have extensive system access and should be carefully reviewed.

[INFO] Analyzing Contact Directory Content Providers
[WARNING] Contact directory provider found: ContactsProvider
[INFO]   Authority: com.example.contacts
[INFO]   Reason: Authority contains contacts-related keyword: com.example.contacts
[CRITICAL] Contact provider ContactsProvider is exported without permissions - HIGH RISK
```

### JSON Output
```json
{
  "Accessibility Services": [
    {
      "name": "CustomAccessibilityService",
      "full_name": "com.example.CustomAccessibilityService", 
      "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "exported": true,
      "enabled": true
    }
  ],
  "Contact Directory Providers": [
    {
      "name": "ContactsProvider",
      "full_name": "com.example.ContactsProvider",
      "authority": "com.example.contacts",
      "permission": null,
      "read_permission": null, 
      "write_permission": null,
      "exported": true,
      "grant_uri_permissions": false,
      "contacts_related_reason": "Authority contains contacts-related keyword: com.example.contacts"
    }
  ]
}
```

## Implementation Files to Modify

### 1. `src/parser.py`
- Add `getAccessibilityServices()` method
- Add `getContactDirectoryProviders()` method  
- Add `_isContactsRelatedProvider()` helper method

### 2. `src/analyzer.py`
- Add `analyzeAccessibilityServices()` method
- Add `analyzeContactDirectoryProviders()` method
- Update `runAllTests()` method to include new analyses

### 3. Test Files (Optional)
- Create test manifests with accessibility services
- Create test manifests with contact directory providers
- Add unit tests for new parser methods

## Security Context

### Accessibility Services Risks
- **Overlay Attacks**: Malware can overlay fake login screens
- **Credential Theft**: Can read password fields and form data
- **UI Automation**: Can perform actions on behalf of user
- **Screen Reading**: Access to all displayed content
- **Input Injection**: Can simulate user interactions

### Contact Directory Provider Risks
- **Privacy Violation**: Exposure of personal contact information
- **Data Leakage**: Unprotected providers can be accessed by other apps
- **Business Intelligence**: Corporate directory information exposure
- **Social Engineering**: Contact lists used for targeted attacks

## Implementation Complexity: **SIMPLE**

This implementation follows existing AMAnDe patterns:
- Uses established XML parsing techniques
- Follows existing namedtuple patterns for data structures
- Uses existing logging and JSON output mechanisms
- Minimal code changes required
- No external dependencies needed

The enhancement integrates seamlessly with the current architecture and maintains consistency with existing code style and patterns.

## Validation Criteria

### Accessibility Services Detection
- [ ] Correctly identifies services with `BIND_ACCESSIBILITY_SERVICE` permission
- [ ] Verifies presence of accessibility intent filter
- [ ] Reports exported status and security implications
- [ ] Includes service details in JSON output

### Contact Directory Providers Detection  
- [ ] Identifies providers with contact-related authorities
- [ ] Detects contact permissions (READ_CONTACTS, WRITE_CONTACTS)
- [ ] Checks meta-data for contact directory indicators
- [ ] Flags security risks for exported providers without permissions
- [ ] Includes provider details and risk assessment in JSON output

### Integration
- [ ] New analyses integrate into main `runAllTests()` flow
- [ ] Console output follows existing AMAnDe formatting patterns
- [ ] JSON output maintains consistent structure
- [ ] No breaking changes to existing functionality

---

**Status**: Ready for Implementation  
**Priority**: Medium-High (Security-focused enhancement)  
**Estimated Effort**: 2-3 hours (Simple implementation following existing patterns)
