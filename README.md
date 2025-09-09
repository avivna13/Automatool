# Automatool - Malware Research Automation Suite

**Automatool** is a comprehensive automation toolkit designed to streamline APK malware analysis workflows, allowing researchers to focus on analysis rather than repetitive setup tasks.

## 🎯 What It Does

Automatool automates the entire APK analysis pipeline from initial setup to comprehensive intelligence gathering, eliminating hours of manual configuration and data collection.

## 🔧 Core Automations

### **Analysis Environment Setup**
- **VPN Verification**: Ensures secure analysis environment
- **Tool Integration**: Auto-launches Jadx GUI and VS Code workspace
- **APK Installation**: Installs APK on connected Android devices via ADB

### **Intelligence Gathering**
- **App Metadata Collection**: Scrapes Google Play Store and SensorTower data
- **Reviews Analysis**: Extracts and summarizes user reviews for behavioral insights  
- **Research Plan Generation**: Creates structured analysis plans from gathered intelligence

### **Security Analysis**
- **Steganography Detection**: Scans APK assets (images, fonts) for hidden data
- **Base64 String Detection**: Identifies encoded content in APK files
- **YARA Rules Processing**: Parses malware detection results into summaries
- **MobSF Integration**: Automated static/dynamic analysis via containerized MobSF

### **AI-Powered Analysis**
- **Gemini Integration**: Leverages Google's Gemini AI for intelligent malware assessment
- **Context-Aware Analysis**: AI analyzes all collected data (reviews, metadata, YARA results) together
- **Automated Reporting**: Generates comprehensive threat assessments and research insights
- **Smart File Processing**: AI can process and correlate findings from multiple analysis outputs

### **Dynamic Analysis**
- **Frida Script Automation**: Copies and configures Frida hooks with package names
- **VPN-Controlled Hooking**: Runs Frida scripts through different VPN locations
- **SSL Unpinning & Bypasses**: Automated root detection, license check, and network bypasses

### **Decompilation & Forensics**
- **Multi-Tool Decompilation**: Jadx, APKTool, APKLeaks integration
- **String Analysis**: Extracts strings from native libraries (.so files)
- **APK Unmask**: Reveals obfuscated APK components

## 🌐 Web Interface (automatool_ui)

The web UI provides a user-friendly interface for:
- **File Upload**: Drag-and-drop APK analysis
- **MobSF Integration**: One-click containerized analysis
- **Gemini AI Analysis**: 
  - Send custom prompts to Google's Gemini AI
  - AI automatically accesses all analysis files in your workspace
  - Context-aware responses based on collected intelligence
  - Automated threat assessment and behavioral analysis
- **Toll Fraud Monitoring**: Real-time SMS/call monitoring dashboard
- **Process Management**: Track and manage running analysis tasks

## 🚀 Why It Matters

**The Setup Nightmare**: Every APK analysis traditionally meant hours of tedious, repetitive setup - manually launching Jadx, configuring VS Code workspaces, scraping app store data, setting up Frida scripts with correct package names, managing VPN connections, running multiple decompilation tools, parsing YARA results, and juggling dozens of terminal windows. It's mind-numbing busywork that kills productivity and researcher motivation.

**Before Automatool**: Researchers spent hours manually configuring tools, collecting metadata, setting up environments, and managing multiple analysis processes.

**With Automatool**: One command launches a complete analysis pipeline - from environment setup to intelligence reports - letting researchers focus on actual malware analysis and threat hunting.

## 📊 Key Benefits

- **Time Savings**: Reduces setup time from hours to minutes
- **Consistency**: Standardized analysis workflow across all APKs
- **Comprehensive Coverage**: Combines static, dynamic, and intelligence analysis
- **Resource Management**: Automatic cleanup and process tracking
- **Scalability**: Web interface enables team collaboration

## 🔍 Perfect For

- Malware researchers analyzing Android threats
- Security teams conducting APK assessments  
- Incident response requiring rapid APK analysis
- Academic research on mobile malware trends

---

*Focus on the malware, not the setup. Let Automatool handle the automation.*
