"""
VPN Switcher Module

Contains the original VPN implementation class for NordVPN.
This module has been adapted from the original VPNSwitcher.py with bug fixes.
"""

import subprocess


class NordVpn:
    """NordVPN controller using nordvpn CLI."""

    @classmethod
    def change_vpn_country(cls, vpn_region):
        """Change VPN to specified country using nordvpn CLI."""
        try:
            current_country = NordVpn.get_current_country()
            if current_country == vpn_region:
                return f"Already connected to a VPN server in {vpn_region}."

            connect_result = subprocess.run(
                ['nordvpn', 'connect', vpn_region], 
                capture_output=True, 
                text=True
            )
            if connect_result.returncode == 0:
                return f"Successfully connected to a VPN server in {vpn_region}."
            else:
                raise Exception(f"Failed to connect to a VPN server in {vpn_region}: {connect_result.stderr}")

        except subprocess.CalledProcessError as e:
            return f"Subprocess error occurred: {e}"
        except Exception as e:
            return f"An error occurred: {e}"

    @classmethod
    def get_current_country(cls):
        """Get current NordVPN connection country."""
        try:
            status_result = subprocess.run(
                ['nordvpn', 'status'], 
                capture_output=True, 
                text=True
            )
            if status_result.returncode != 0:
                raise Exception(f"Failed to get VPN status: {status_result.stderr}")

            status_output = status_result.stdout
            for line in status_output.splitlines():
                if "Country:" in line:
                    return line.split(":")[1].strip().lower()
            return None
        except subprocess.CalledProcessError as e:
            return f"Subprocess error occurred: {e}"
        except Exception as e:
            return f"An error occurred: {e}"

    @classmethod
    def get_available_countries(cls):
        """Get list of available NordVPN countries."""
        try:
            countries_result = subprocess.run(
                ['nordvpn', 'countries'], 
                capture_output=True, 
                text=True
            )
            if countries_result.returncode != 0:
                raise Exception(f"Failed to get VPN countries: {countries_result.stderr}")

            countries_output = countries_result.stdout
            return [country for line in countries_output.splitlines() for country in line.split()]

        except subprocess.CalledProcessError as e:
            return f"Subprocess error occurred: {e}"
        except Exception as e:
            print(f"An error occurred: {e}")
            return None


if __name__ == "__main__":
    print(NordVpn.get_current_country())
