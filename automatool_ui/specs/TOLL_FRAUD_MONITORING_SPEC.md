# Toll Fraud Monitoring System Specification
## Simplified Two-Module Approach

### Overview
A streamlined monitoring system that detects toll fraud applications using only two core modules:
1. **Notification Monitor** - Monitors app notifications for suspicious patterns
2. **SMS/Call Monitor** - Tracks SMS and call activities for fraud indicators

### System Architecture

```
automatool/
└── src/
    └── scripts/
        ├── monitoring/                    # Monitoring package
        │   ├── __init__.py
        │   ├── notification_monitor.py    # Notification monitoring
        │   ├── sms_call_monitor.py       # SMS/Call monitoring
        │   └── fraud_detector.py         # Simple correlation
        └── utils/
            └── adb_controller.py         # ADB command execution

automatool_ui/                           # UI integration
├── templates/
│   └── monitoring_dashboard.html        # Simple monitoring UI
└── app.py                               # Flask app with monitoring endpoints
```

### 1. Notification Monitor

**Purpose**: Monitor notification listener traffic specifically from the target app for focused toll fraud detection

**ADB Commands**: 
- Target app specific: `adb shell dumpsys notification | grep "TARGET_PACKAGE_NAME"`
- Target app listener traffic: `adb shell dumpsys notification | grep -E "(TARGET_PACKAGE_NAME|listener|notification)" | grep "TARGET_PACKAGE_NAME"`
- Focused monitoring: `adb shell dumpsys notification --listeners | grep "TARGET_PACKAGE_NAME"`

**Output Format**:
```json
{
  "timestamp": "2025-08-29T10:30:00.000Z",
  "target_app": "com.target.app",
  "target_app_notifications": [
    {
      "line": "android:title=Premium Service Subscription",
      "pattern": "premium",
      "listener_activity": "notification_listener"
    },
    {
      "line": "android:text=Your account will be charged $9.99",
      "pattern": "charged", 
      "listener_activity": "notification_listener"
    },
    {
      "line": "android:package=com.target.app",
      "pattern": "package_activity",
      "listener_activity": "package_activity"
    },
    {
      "line": "android:listener=NotificationListenerService",
      "pattern": "listener_events",
      "listener_activity": "listener_events"
    }
  ],
  "target_app_traffic_summary": {
    "total_target_notifications": 12,
    "listener_activities": 8,
    "package_activities": 4
  }
}
```

**Detection Patterns**:
- `premium` - Premium service references in target app
- `subscription` - Subscription-related content in target app
- `billing` - Billing or payment content in target app
- `charged` - Charging or payment content in target app
- `toll` - Toll-related content in target app
- `fraud` - Fraud-related content in target app
- `notification_listener` - Target app notification listener activities
- `package_activity` - Target app package-related notification traffic
- `listener_events` - Target app notification listener events and callbacks
- `listener_behavior` - Target app notification listener behavior patterns
- `notification_metadata` - Target app notification metadata and attributes

### 2. SMS/Call Monitor

**Purpose**: Monitor SMS and call activities specifically from the target app for suspicious patterns

**ADB Commands**:
- Target app SMS: `adb shell dumpsys telephony.registry | grep "TARGET_PACKAGE_NAME"`
- Target app calls: `adb shell dumpsys telephony.registry | grep "TARGET_PACKAGE_NAME"`
- Target app telephony: `adb shell dumpsys telephony.registry | grep -E "(TARGET_PACKAGE_NAME|SMS|CALL)"`

**Output Format**:
```json
{
  "timestamp": "2025-08-29T10:30:00.000Z",
  "target_app": "com.target.app",
  "target_app_sms": [
    {
      "number": "+1234567890",
      "message": "You have been subscribed to Premium Service",
      "pattern": "subscribed"
    }
  ],
  "target_app_calls": [
    {
      "number": "+1234567890",
      "duration": "00:00:15",
      "pattern": "short_duration_premium"
    }
  ]
}
```

**Detection Patterns**:
- SMS: `subscribed`, `premium`, `service`, `charge`, `billing` (from target app)
- Calls: `short_duration_premium` (calls under 30 seconds to premium numbers from target app)

### 3. Simple Data Collector

**Purpose**: Collect and output raw notification data from the target app without analysis

**Output Format**:
```json
{
  "timestamp": "2025-08-29T10:30:00.000Z",
  "target_app": "com.target.app",
  "total_notifications": 12,
  "raw_notifications": [
    {
      "line": "android:title=Premium Service Subscription",
      "pattern": "premium",
      "listener_activity": "notification_listener"
    }
  ],
  "collection_summary": {
    "lines_collected": 12,
    "collection_time": "2025-08-29T10:30:00.000Z"
  }
}
```

### 4. Implementation Requirements

#### File Structure
```
automatool/src/scripts/
├── monitoring/
│   ├── __init__.py
│   ├── notification_monitor.py
│   ├── sms_call_monitor.py
│   └── fraud_detector.py
└── utils/
    └── adb_controller.py

automatool_ui/
└── templates/
    └── monitoring_dashboard.html
```

#### Core Functions

**Notification Monitor**:
```python
def get_notifications(package_name=None)
def analyze_notifications(raw_data)
```

**SMS/Call Monitor**:
```python
def get_sms_logs()
def get_call_logs()
def analyze_sms_calls(raw_data)
```

**Data Collector**:
```python
def collect_notifications(notification_data)
```

#### ADB Controller
```python
def execute_command(cmd, timeout=30)
```

#### Import Structure
```python
# From automatool_ui/app.py
from automatool.automatool.src.scripts.monitoring import NotificationMonitor, DataCollector
from automatool.automatool.src.scripts.utils.adb_controller import ADBController

# Or using relative imports if in the same project
from ..automatool.automatool.src.scripts.monitoring import NotificationMonitor, DataCollector
from ..automatool.automatool.src.scripts.utils.adb_controller import ADBController
```

### 5. Integration Points

#### New API Endpoints
```python
@app.route('/api/monitoring/notifications', methods=['GET'])
@app.route('/api/monitoring/sms-calls', methods=['GET'])
@app.route('/api/monitoring/collect-data', methods=['GET'])
```

#### UI Components
- Simple monitoring dashboard
- Real-time notification display
- SMS/Call activity log
- Data collection summary

### 6. Success Criteria

1. **Notification Monitor**: Successfully detects suspicious notification patterns
2. **Data Collection**: Successfully collects and outputs raw notification data
4. **Performance**: Real-time monitoring with minimal latency
5. **Reliability**: Stable ADB command execution and data parsing
6. **Integration**: Successfully imports monitoring modules from scripts directory
7. **Modularity**: Monitoring system works independently and can be imported by other components

### 7. Limitations

- Only monitors notifications and listener activities
- No permission auditing
- No network traffic analysis
- No dynamic behavior analysis
- Basic correlation logic

### 8. Future Enhancements

- Add permission monitoring
- Include network traffic analysis
- Implement machine learning correlation
- Add historical data analysis
- Include user notification preferences

### 9. Benefits of Scripts Directory Placement

- **Reusability**: Monitoring modules can be imported by other parts of the automatool system
- **Separation of Concerns**: Core monitoring logic is separate from UI components
- **Maintainability**: Easier to maintain and update monitoring logic independently
- **Testing**: Can test monitoring modules separately from the UI
- **Integration**: Other automation scripts can leverage the monitoring capabilities
- **Consistency**: Follows the existing automatool project structure

---

**Note**: This simplified approach focuses on the two most effective detection methods while maintaining a lightweight, maintainable system that can be easily extended in the future.
