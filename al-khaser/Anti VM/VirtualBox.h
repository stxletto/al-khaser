#include <Windows.h>
#include <tchar.h>
#include <ShlObj.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <Wbemidl.h>

# pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")


#include "../Shared/Common.h"
#include "../Shared/Utils.h"




VOID vbox_reg_key_value();
VOID vbox_reg_keys();
VOID vbox_files();
BOOL vbox_dir();

BOOL vbox_check_mac();
VOID vbox_devices();
BOOL vbox_window_class();
BOOL vbox_network_share();
VOID vbox_processes();
BOOL vbox_devices_wmi();
BOOL vbox_mac_wmi();
BOOL vbox_eventlogfile_wmi();


typedef int(*wmi_check_row) (IWbemClassObject *);
int wmi_initialize(const wchar_t *, IWbemServices **);
int wmi_check_query(IWbemServices *, const wchar_t *, const wchar_t *,	wmi_check_row check_row);
void wmi_cleanup(IWbemServices *);
int vbox_wmi_check_row(IWbemClassObject *row);
int vbox_wmi_devices();