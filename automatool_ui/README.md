# Automatool UI

This is the web interface for the Automatool project. It allows you to upload APK files and run various analysis tasks, including MobSF analysis.

## MobSF Analysis Setup

Running the MobSF analysis requires Docker. By default, Docker commands need to be run with `sudo`, which can cause issues when triggering the analysis from a web application. This document explains how to configure your system to allow the Automatool UI to run MobSF analysis.

### The Problem

When the MobSF analysis is started from the web UI, it needs to run Docker commands to start the MobSF container. If the user running the web application does not have permission to run Docker commands, the analysis will fail with a "permission denied" error.

### The Solution

There are two ways to solve this problem. Choose the one that best suits your security needs.

#### Option 1: Add Your User to the `docker` Group (Recommended)

This is the simplest and most common way to grant a user permission to run Docker commands.

**1. Add your user to the `docker` group:**

Open a terminal and run the following command:

```bash
sudo usermod -aG docker $USER
```

**2. Log out and log back in:**

This is a crucial step. You must log out of your system and then log back in for the group membership change to take effect.

**Security Note:** Adding a user to the `docker` group gives them root-equivalent permissions on the host system. Be aware of the security implications of this choice.

#### Option 2: Configure Passwordless `sudo` for Docker (Advanced)

This method is more secure because it allows you to grant passwordless `sudo` access only for the `docker` command, without giving the user full root-equivalent permissions.

**1. Open the `sudoers` file for editing:**

Use the `visudo` command to safely edit the `/etc/sudoers` file.

```bash
sudo visudo
```

**2. Add the `NOPASSWD` rule:**

Scroll to the bottom of the file and add the following line. Replace `kali` with your username if it's different.

```
kali ALL=(ALL) NOPASSWD: /usr/bin/docker
```

**3. Save and exit the file.**

After making this change, the web application will be able to run `sudo docker` commands without a password prompt.

### Port Configuration

By default, the MobSF container is configured to run on port `8080`. If you need to change this, you can edit the `utils/process_manager.py` file.

In the `execute_mobsf_upload` function, you will find the `--port` argument set to `8080`. You can change the value of this argument to the desired port.
