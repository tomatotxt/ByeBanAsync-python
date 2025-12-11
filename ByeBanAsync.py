
import os
import sys
import subprocess
import winreg
import random
import ctypes
import json

def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def delete_roblox_cookies():
    """Finds and deletes the Roblox cookie file."""
    print("[*] Attempting to delete Roblox cookies...")
    try:
        user_profile = os.environ.get("USERPROFILE")
        if not user_profile:
            print("[!!!] Could not find USERPROFILE environment variable.")
            return

        cookie_path = os.path.join(user_profile, "AppData", "Local", "Roblox", "LocalStorage", "RobloxCookies.dat")

        if os.path.exists(cookie_path):
            os.remove(cookie_path)
            print(f"[âˆš] Roblox cookie file has been deleted from '{cookie_path}'!")
        else:
            print(f"[!] Roblox cookie file not found at '{cookie_path}'.")

    except Exception as e:
        print(f"[!!!] Failed to delete Roblox cookie file! Err: {e}")

def get_network_adapters():
    """Lists available network adapters using PowerShell's Get-NetAdapter."""
    adapters = []
    try:
        # Using PowerShell is more modern and reliable than the deprecated wmic.
        # This command gets adapters, renames properties to match the script's old keys, and converts to JSON.
        command = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetAdapter | Select-Object @{Name='NetConnectionID';Expression={$_.Name}}, @{Name='Description';Expression={$_.InterfaceDescription}} | ConvertTo-Json"
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            encoding='utf-8'
        )

        raw_json = result.stdout
        # JSON output might be a single object if one adapter, or an array if multiple.
        # We handle this by checking if the output starts with '['.
        if raw_json.strip() and not raw_json.strip().startswith('['):
            raw_json = f"[{raw_json}]"

        adapter_data = json.loads(raw_json)

        # The DeviceID from wmic isn't available here and wasn't used reliably in the original script.
        # The set_mac_address_by_description function, which works, is used instead.
        for item in adapter_data:
             if item.get('NetConnectionID'): # Ensure adapter has a name
                item['DeviceID'] = '0' # Placeholder, as the robust function doesn't use it
                adapters.append(item)

    except FileNotFoundError:
        print("[!!!] PowerShell not found. Please ensure it's installed and in your system's PATH.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[!!!] PowerShell command failed: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        print(f"[!!!] Failed to parse adapter data from PowerShell: {e}")
        print(f"Raw output: {result.stdout}")
        return []
    except Exception as e:
        print(f"[!!!] An unexpected error occurred while listing network adapters: {e}")
    return adapters


def generate_mac_address():
    """Generates a random, locally administered MAC address."""
    # Start with '02' to signify a locally administered, unicast address
    mac = [0x02]
    for _ in range(5):
        mac.append(random.randint(0x00, 0xff))
    return "".join([f"{b:02X}" for b in mac])

def set_mac_address(adapter_device_id, new_mac):
    """Sets the 'NetworkAddress' registry value for the specified adapter."""
    try:
        reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}"
        hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        
        for i in range(winreg.QueryInfoKey(hkey)[0]):
            subkey_name = winreg.EnumKey(hkey, i)
            if subkey_name.isdigit(): # Adapter keys are typically 4-digit numbers
                try:
                    adapter_key = winreg.OpenKey(hkey, subkey_name)
                    device_id_val, _ = winreg.QueryValueEx(adapter_key, "NetCfgInstanceId")
                    if device_id_val == adapter_device_id:
                        # Found the correct adapter, now open it with write access
                        writable_key = winreg.OpenKey(hkey, subkey_name, 0, winreg.KEY_WRITE)
                        winreg.SetValueEx(writable_key, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
                        winreg.CloseKey(writable_key)
                        winreg.CloseKey(adapter_key)
                        print(f"[>] Setting 'NetworkAddress' to '{new_mac}'")
                        print("[âˆš] Successfully updated registry for MAC address.")
                        return True
                    winreg.CloseKey(adapter_key)
                except FileNotFoundError:
                    continue # Some subkeys might not have the value
                except Exception as e:
                    print(f"[!!!] Error processing subkey {subkey_name}: {e}")
                    continue
        
        winreg.CloseKey(hkey)
        print(f"[!!!] Could not find a matching registry entry for adapter with DeviceID: {adapter_device_id}")

    except Exception as e:
        print(f"[!!!] Failed to set MAC address in registry: {e}")
    
    return False

def restart_adapter(connection_name):
    """Disables and then re-enables a network adapter."""
    print(f"[>] Attempting to restart network adapter '{connection_name}' to apply changes...")
    try:
        print(f"[>] Disabling adapter: '{connection_name}'")
        subprocess.run(f"netsh interface set interface name=\"{connection_name}\" admin=disabled", check=True, capture_output=True)
        print(f"[>] Enabling adapter: '{connection_name}'")
        subprocess.run(f"netsh interface set interface name=\"{connection_name}\" admin=enabled", check=True, capture_output=True)
        print(f"[âˆš] Network adapter '{connection_name}' restarted. MAC address change should now be active.")
        print("[i] Verify with 'ipconfig /all' or 'getmac'.")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode('utf-8', errors='ignore').strip()
        print(f"[!!!] Failed to restart adapter. This command requires administrator privileges.")
        if error_output:
            print(f"[!!!] Error details: {error_output}")
    except Exception as e:
        print(f"[!!!] An unexpected error occurred while restarting the adapter: {e}")

def spoof_mac_address():
    """Guides the user through the MAC address spoofing process."""
    if not is_admin():
        print("[!!!] MAC address spoofing requires administrator privileges. Please re-run as administrator.")
        return

    print("\n--- MAC Address Spoofing ---")
    choice = input("[?] Do you want to attempt to change your MAC address? (y/n): ").lower()
    if choice != 'y':
        return

    adapters = get_network_adapters()
    if not adapters:
        print("[!] No suitable network adapters found.")
        return

    print("[i] Available network adapters:")
    for i, adapter in enumerate(adapters):
        print(f"  [{i+1}]: {adapter.get('Description', 'N/A')}")
        print(f"     â””â”€ Connection Name: '{adapter.get('NetConnectionID', 'N/A')}'")
    
    try:
        selection = int(input("\n[?] Enter the number of the adapter to change: ")) - 1
        if 0 <= selection < len(adapters):
            selected_adapter = adapters[selection]
            new_mac = generate_mac_address()
            
            # We need the full DeviceID from the registry (NetCfgInstanceId) to be sure
            # but the wmic DeviceID is just a number. We need to find the correct key.
            # The most reliable way is to iterate and match NetCfgInstanceId, but that's complex.
            # A simpler way for this clone is to hope the 4-digit key name matches DeviceID padded.
            # A more robust solution is needed for a real tool, but for this clone, we proceed.
            adapter_id_for_reg = f"{int(selected_adapter['DeviceID']):04d}"

            print(f"[>] Attempting to set MAC for adapter: '{selected_adapter['Description']}' (ID: {adapter_id_for_reg})...")
            
            # Unfortunately, mapping DeviceID to the registry key is not straightforward.
            # We will search based on a known property like DriverDesc.
            if set_mac_address_by_description(selected_adapter['Description'], new_mac):
                restart_adapter(selected_adapter['NetConnectionID'])

        else:
            print("[!!!] Invalid selection.")
    except ValueError:
        print("[!!!] Invalid input. Please enter a number.")
    except Exception as e:
        print(f"[!!!] An error occurred during MAC spoofing: {e}")

def set_mac_address_by_description(adapter_description, new_mac):
    """Finds the adapter by its 'DriverDesc' and sets the 'NetworkAddress' value."""
    try:
        reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}"
        hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        
        for i in range(winreg.QueryInfoKey(hkey)[0]):
            subkey_name = winreg.EnumKey(hkey, i)
            if subkey_name.isdigit():
                try:
                    adapter_key = winreg.OpenKey(hkey, subkey_name)
                    driver_desc, _ = winreg.QueryValueEx(adapter_key, "DriverDesc")
                    if driver_desc == adapter_description:
                        writable_key = winreg.OpenKey(hkey, subkey_name, 0, winreg.KEY_WRITE)
                        winreg.SetValueEx(writable_key, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
                        winreg.CloseKey(writable_key)
                        winreg.CloseKey(adapter_key)
                        print(f"[>] Setting 'NetworkAddress' to '{new_mac}'")
                        print("[âˆš] Successfully updated registry for MAC address.")
                        return True
                    winreg.CloseKey(adapter_key)
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        
        winreg.CloseKey(hkey)
        print(f"[!!!] Could not find a matching registry entry for adapter description: '{adapter_description}'")
    except Exception as e:
        print(f"[!!!] Failed to set MAC address in registry: {e}")
    
    return False


def main():
    """Main function to run the ByeBanAsync clone."""
    print("[?] ByeBanAsync v2.2 (Python Clone) | centerepic")
    print("[!] Ensure you are logged out of the banned account before running this program!")
    
    delete_roblox_cookies()
    spoof_mac_address()
    
    input("\n[...] Press Enter to exit...")

if __name__ == "__main__":
    main()
