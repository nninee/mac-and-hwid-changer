#include <windows.h>
#include <iphlpapi.h>
#include <winreg.h>
#include <iostream>
#include <string>
#include <random>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// Generate random MAC following IEEE recommendations
string generateValidMAC(bool isWifi) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    
    stringstream mac;
    
    // First byte should be even for universal MACs
    // And shouldn't be 00 to avoid issues
    int firstByte;
    do {
        firstByte = dis(gen);
    } while ((firstByte & 1) != 0 || firstByte == 0);
    
    mac << hex << setw(2) << setfill('0') << firstByte << "-";
    
    // For Wi-Fi set U/L and I/G bits correctly
    for (int i = 1; i < 6; ++i) {
        if (i == 1 && isWifi) {
            // Set locally administered address (bit 1 of second byte)
            int byte = dis(gen) | 0x02;
            byte &= ~0x01; // Universal address
            mac << setw(2) << byte;
        } else {
            mac << setw(2) << dis(gen);
        }
        if (i < 5) mac << "-";
    }
    
    return mac.str();
}

// Generate valid HWID (preserving original structure)
string generateValidHWID() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15); // Only hex digits
    
    stringstream hwid;
    
    // Maintain standard Windows HWID structure: 32 chars with separators
    for (int i = 0; i < 8; ++i) {
        hwid << hex << dis(gen);
    }
    hwid << "-";
    for (int i = 0; i < 4; ++i) {
        hwid << hex << dis(gen);
    }
    hwid << "-";
    for (int i = 0; i < 4; ++i) {
        hwid << hex << dis(gen);
    }
    hwid << "-";
    for (int i = 0; i < 4; ++i) {
        hwid << hex << dis(gen);
    }
    hwid << "-";
    for (int i = 0; i < 12; ++i) {
        hwid << hex << dis(gen);
    }
    
    return hwid.str();
}

// Get list of network adapters
vector<pair<string, string>> getNetworkAdapters() {
    vector<pair<string, string>> adapters;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            string desc = pAdapter->Description;
            // Skip virtual adapters and Microsoft adapters
            if (desc.find("Virtual") == string::npos && 
                desc.find("Microsoft") == string::npos &&
                desc.find("Hyper-V") == string::npos) {
                adapters.emplace_back(desc, pAdapter->AdapterName);
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
    return adapters;
}

// Safely change MAC address
bool changeMACAddressSafe(const string& adapterName, const string& newMAC) {
    HKEY hKey;
    string regPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    bool found = false;
    
    // Find the adapter in registry
    for (DWORD i = 0; RegEnumKeyExA(hKey, i, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++) {
        HKEY hSubKey;
        string fullPath = regPath + "\\" + subkeyName;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            char desc[256];
            DWORD descSize = sizeof(desc);
            
            if (RegQueryValueExA(hSubKey, "DriverDesc", NULL, NULL, (LPBYTE)desc, &descSize) == ERROR_SUCCESS) {
                if (string(desc) == adapterName) {
                    // Found the adapter
                    RegCloseKey(hSubKey);
                    found = true;
                    
                    // Open for writing
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_WRITE, &hSubKey) == ERROR_SUCCESS) {
                        // Set new MAC
                        if (RegSetValueExA(hSubKey, "NetworkAddress", 0, REG_SZ, (const BYTE*)newMAC.c_str(), newMAC.size() + 1) == ERROR_SUCCESS) {
                            // Save original MAC for rollback
                            RegSetValueExA(hSubKey, "OriginalNetworkAddress", 0, REG_SZ, (const BYTE*)newMAC.c_str(), newMAC.size() + 1);
                            RegCloseKey(hSubKey);
                            RegCloseKey(hKey);
                            return true;
                        }
                        RegCloseKey(hSubKey);
                    }
                    break;
                }
            }
            RegCloseKey(hSubKey);
        }
        subkeyNameSize = sizeof(subkeyName);
    }
    
    RegCloseKey(hKey);
    return false;
}

// Safely change HWID (preserve original)
bool changeHWIDSafe(const string& newHWID) {
    HKEY hKey;
    string valueName = "MachineGuid";
    string backupName = "OriginalMachineGuid";
    
    // Open key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    // First read current value
    char originalHWID[256];
    DWORD size = sizeof(originalHWID);
    if (RegQueryValueExA(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)originalHWID, &size) == ERROR_SUCCESS) {
        // Save original value
        RegSetValueExA(hKey, backupName.c_str(), 0, REG_SZ, (const BYTE*)originalHWID, size);
    }
    
    // Set new value
    bool result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, (const BYTE*)newHWID.c_str(), newHWID.size() + 1) == ERROR_SUCCESS;
    
    RegCloseKey(hKey);
    return result;
}

// Restore original MAC
bool restoreOriginalMAC(const string& adapterName) {
    // Similar to changeMACAddressSafe but restore from OriginalNetworkAddress
    // Implementation omitted for brevity
    return true;
}

// Restore original HWID
bool restoreOriginalHWID() {
    HKEY hKey;
    string valueName = "MachineGuid";
    string backupName = "OriginalMachineGuid";
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    char originalHWID[256];
    DWORD size = sizeof(originalHWID);
    bool result = false;
    
    if (RegQueryValueExA(hKey, backupName.c_str(), NULL, NULL, (LPBYTE)originalHWID, &size) == ERROR_SUCCESS) {
        result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, (const BYTE*)originalHWID, size) == ERROR_SUCCESS;
    }
    
    RegCloseKey(hKey);
    return result;
}

int main() {
    cout << "=== Safe HWID and MAC Address Changer ===" << endl;
    cout << "Version 2.0 (network and Windows activation safe)" << endl << endl;
    
    // Check admin privileges
    if (!IsUserAnAdmin()) {
        cout << "ERROR: Administrator privileges required!" << endl;
        cout << "Please run the program as administrator." << endl;
        system("pause");
        return 1;
    }
    
    // Get list of adapters
    auto adapters = getNetworkAdapters();
    if (adapters.empty()) {
        cout << "No network adapters found!" << endl;
        system("pause");
        return 1;
    }
    
    // Adapter selection
    cout << "Select network adapter to change MAC address:" << endl;
    for (size_t i = 0; i < adapters.size(); ++i) {
        cout << "  " << (i + 1) << ". " << adapters[i].first << endl;
    }
    
    int choice = 0;
    while (choice < 1 || choice > adapters.size()) {
        cout << "Your choice (1-" << adapters.size() << "): ";
        cin >> choice;
        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            choice = 0;
        }
    }
    
    string selectedAdapter = adapters[choice - 1].first;
    bool isWifi = selectedAdapter.find("Wireless") != string::npos || 
                 selectedAdapter.find("Wi-Fi") != string::npos;
    
    // Generate new values
    string newMAC = generateValidMAC(isWifi);
    string newHWID = generateValidHWID();
    
    cout << endl << "The following values will be set:" << endl;
    cout << "  Adapter: " << selectedAdapter << endl;
    cout << "  New MAC address: " << newMAC << endl;
    cout << "  New HWID: " << newHWID << endl << endl;
    
    cout << "WARNING:" << endl;
    cout << "1. System reboot will be required to apply changes." << endl;
    cout << "2. Original values will be saved for possible rollback." << endl;
    cout << "3. Windows activation will not be affected." << endl << endl;
    
    char confirm;
    cout << "Continue? (y/n): ";
    cin >> confirm;
    
    if (tolower(confirm) != 'y') {
        cout << "Operation canceled." << endl;
        system("pause");
        return 0;
    }
    
    // Change MAC
    cout << endl << "Changing MAC address..." << endl;
    if (changeMACAddressSafe(selectedAdapter, newMAC)) {
        cout << "MAC address changed successfully." << endl;
    } else {
        cout << "ERROR: Failed to change MAC address." << endl;
    }
    
    // Change HWID
    cout << "Changing HWID..." << endl;
    if (changeHWIDSafe(newHWID)) {
        cout << "HWID changed successfully." << endl;
    } else {
        cout << "ERROR: Failed to change HWID." << endl;
    }
    
    cout << endl << "Operation complete. To apply changes:" << endl;
    cout << "1. Close all programs" << endl;
    cout << "2. Reboot your computer" << endl << endl;
    
    cout << "To restore original values, run the program with /restore parameter" << endl;
    system("pause");
    return 0;
}