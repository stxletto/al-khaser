#include "VirtualBox.h"


/*
Registry key values
*/

VOID vbox_reg_key_value()
{
	/* Array of strings of blacklisted registry key values */
	TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosVersion"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("VideoBiosVersion"), _T("VIRTUALBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosDate"), _T("06/23/99") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (int i = 0; i < dwLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key HARDWARE\\Description\\System - %s is set to %s:"), szEntries[i][1], szEntries[i][2]);
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

/*
Check against virtualbox registry keys
*/
VOID vbox_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	TCHAR* szKeys[] = {
		_T("HARDWARE\\ACPI\\DSDT\\VBOX__"),
		_T("HARDWARE\\ACPI\\FADT\\VBOX__"),
		_T("HARDWARE\\ACPI\\RSDT\\VBOX__"),
		_T("SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxGuest"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxMouse"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxService"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxSF"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxVideo")
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s: "), szKeys[i]);
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check against virtualbox blacklisted files
*/
VOID vbox_files()
{
	/* Array of strings of blacklisted paths */
	TCHAR* szPaths[] = {
		_T("system32\\drivers\\VBoxMouse.sys"),
		_T("system32\\drivers\\VBoxGuest.sys"),
		_T("system32\\drivers\\VBoxSF.sys"),
		_T("system32\\drivers\\VBoxVideo.sys"),
		_T("system32\\vboxdisp.dll"),
		_T("system32\\vboxhook.dll"),
		_T("system32\\vboxmrxnp.dll"),
		_T("system32\\vboxogl.dll"),
		_T("system32\\vboxoglarrayspu.dll"),
		_T("system32\\vboxoglcrutil.dll"),
		_T("system32\\vboxoglerrorspu.dll"),
		_T("system32\\vboxoglfeedbackspu.dll"),
		_T("system32\\vboxoglpackspu.dll"),
		_T("system32\\vboxoglpassthroughspu.dll"),
		_T("system32\\vboxservice.exe"),
		_T("system32\\vboxtray.exe"),
		_T("system32\\VBoxControl.exe"),
	};

	/* Getting Windows Directory */
	WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szPath[MAX_PATH] = _T("");
	GetWindowsDirectory(szWinDir, MAX_PATH);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		PathCombine(szPath, szWinDir, szPaths[i]);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking file %s: "), szPath);
		if (is_FileExists(szPath))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check against virtualbox blacklisted directories
*/
BOOL vbox_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("oracle\\virtualbox guest additions\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}


/*
Check virtualbox NIC MAC address
*/
BOOL vbox_check_mac()
{
	/* VirtualBox mac starts with 08:00:27 */
	return check_mac_addr(_T("\x08\x00\x27"));
}



/*
Check against pseaudo-devices
*/
VOID vbox_devices()
{
	TCHAR *devices[] = {
		_T("\\\\.\\VBoxMiniRdrDN"),
		_T("\\\\.\\VBoxGuest"),
		_T("\\\\.\\pipe\\VBoxMiniRdDN"),
		_T("\\\\.\\VBoxTrayIPC"),
		_T("\\\\.\\pipe\\VBoxTrayIPC")
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking device %s: "), devices[i]);
		if (hFile != INVALID_HANDLE_VALUE)
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

/*
Check for Window class
*/
BOOL vbox_window_class()
{
	HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
	HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

	if (hClass || hWindow)
		return TRUE;
	else
		return FALSE;
}

/*
Check for shared folders network profider
*/
typedef DWORD(__stdcall* funcWNGetProviderName)(DWORD, LPTSTR, LPDWORD);
BOOL vbox_network_share()
{
	//DWORD dwCount = 4096;
	//DWORD dwSize = 4096 * sizeof(TCHAR);
	//TCHAR * pProvider = (TCHAR *)LocalAlloc(LMEM_ZEROINIT, dwCount);

	DWORD dwSize = MAX_PATH;
	TCHAR pProvider[MAX_PATH] = _T("");
	
	OutputDebugString(_T("WNetGetProviderName"));
	
	
	funcWNGetProviderName pWNetGetProviderName;
	//_tprintf(TEXT("\n WNetGetProviderName begin.. 0x%08x\n"), (DWORD)&WNetGetProviderName);
	HMODULE hMprDLL = LoadLibrary(_T("mpr.dll"));
	pWNetGetProviderName = (funcWNGetProviderName)GetProcAddress(hMprDLL, "WNetGetProviderNameW");
	if (NULL == pWNetGetProviderName) {
		_tprintf(TEXT("\n WNetGetProviderName get failed. 0x%08x\n"), (DWORD)&pWNetGetProviderName);
		return FALSE;
	}


	if (pWNetGetProviderName(WNNC_NET_RDR2SAMPLE, pProvider, &dwSize) == NO_ERROR) {
		OutputDebugString(pProvider);
		_tprintf(TEXT("\n WNetGetProviderName end..\n"));
		if (StrCmpI(pProvider, _T("VirtualBox Shared Folders")) == 0)
			return TRUE;
		else
			return FALSE;
	}
	return FALSE;
}

/*
Check for process list
*/

VOID vbox_processes()
{
	TCHAR *szProcesses[] = {
		_T("vboxservice.exe"),
		_T("vboxtray.exe")
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking virtual box processe %s: "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/**
* Initialise the WMI client that will connect to the local machine WMI
* namespace. It will return TRUE if the connection was successful, FALSE
* otherwise.
*/
int wmi_initialize(const wchar_t *query_namespace, IWbemServices **pSvc) {
	BSTR bstrNamespace;
	//IWbemLocator *locator = NULL;
	int iRetn = 0;

	// Initialize COM
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		return FALSE;
	}

	_tprintf(TEXT("\n CoCreateInstance begin..\n"));
	IWbemLocator *pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres)) {
		CoUninitialize();
		return FALSE;
	}

	_tprintf(TEXT("\n CoCreateInstance end..\n"));
	bstrNamespace = SysAllocString(query_namespace);

	// Connect to the namespace with the current user and obtain pointer
	// services to make IWbemServices calls.
	
	_tprintf(TEXT("\n pLoc->ConnectServer begin..\n"));
	hres = pLoc->ConnectServer(
		bstrNamespace, // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		pSvc                    // pointer to IWbemServices proxy
	);

	iRetn = FAILED(hres) ? FALSE : TRUE;

	_tprintf(TEXT("\n pLoc->ConnectServer end..\n"));
	SysFreeString(bstrNamespace);
	//pLoc->Release();

	_tprintf(TEXT("\n wmi_initialize end..\n"));
	return iRetn;
}


/**
* Check if the device identifier ("PCI\\VEN_80EE&DEV_CAFE") in the returned rows.
*/
int vbox_wmi_check_row(IWbemClassObject *row) {
	CIMTYPE type = CIM_ILLEGAL;
	VARIANT value;

	HRESULT hresult = row->Get(L"DeviceId", 0, &value, &type, 0);

	if (FAILED(hresult) || V_VT(&value) == VT_NULL || type != CIM_STRING) {
		return FALSE;
	}

	return (wcsstr(V_BSTR(&value), L"PCI\\VEN_80EE&DEV_CAFE") != NULL) ? TRUE : FALSE;
}

/**
* Check for devices VirtualBox devices using WMI.
*/
int vbox_wmi_devices() {
	IWbemServices *services = NULL;

	_tprintf(TEXT("\n wmi_initialize begin..\n"));
	if (wmi_initialize(L"root\\cimv2", &services) != TRUE) {
		return FALSE;
	}

	_tprintf(TEXT("\n wmi_initialize ok..\n"));
	int result = wmi_check_query(services, L"WQL", L"SELECT DeviceId FROM Win32_PnPEntity",
		&vbox_wmi_check_row);

	_tprintf(TEXT("\n wmi_check_query ok..\n"));
	wmi_cleanup(services);

	_tprintf(TEXT("\n wmi_cleanup ok..\n"));

	return result;
}


/**
* Execute the suplied WMI query and call the row checking function for each row returned.
*/
int wmi_check_query(IWbemServices *services, const wchar_t *language, const wchar_t *query,
	wmi_check_row check_row) {
	int status = FALSE;
	IEnumWbemClassObject *queryrows = NULL;
	BSTR wmilang = SysAllocString(language);
	BSTR wmiquery = SysAllocString(query);

	// Execute the query.
	HRESULT result = services->ExecQuery(wmilang, wmiquery, WBEM_FLAG_BIDIRECTIONAL, NULL, &queryrows);

	if (!FAILED(result) && (queryrows != NULL)) {
		IWbemClassObject * batchrows[10];
		ULONG index, count = 0;
		result = WBEM_S_NO_ERROR;

		while (WBEM_S_NO_ERROR == result && status == FALSE) {
			// Retrieve 10 rows (instances) each time.
			result = queryrows->Next(WBEM_INFINITE, 10,
				batchrows, &count);

			if (!SUCCEEDED(result)) {
				continue;
			}

			for (index = 0; index < count && status == FALSE; index++) {
				status = check_row(batchrows[index]);

				batchrows[index]->Release();
			}
		}

		queryrows->Release();
	}

	SysFreeString(wmiquery);
	SysFreeString(wmilang);

	return status;
}

/**
* Cleanup WMI.
*/
void wmi_cleanup(IWbemServices *services) {
	if (services != NULL) {
		services->Release();
	}

	CoUninitialize();
}


/*
Check vbox devices using WMI
*/
BOOL vbox_devices_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc);
	
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_PnPEntity"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("DeviceId"), 0, &vtProp, 0, 0);
				
				// Do our comparaison
				if (_tcsstr(vtProp.bstrVal, _T("PCI\\VEN_80EE&DEV_CAFE")) != 0)
				{
					bFound = TRUE;
					break;
				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
			}

			// Cleanup
			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check vbox mac @ using WMI
*/
BOOL vbox_mac_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc);
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NetworkAdapterConfiguration"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("MACAddress"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					// Do our comparaison
					if (_tcsstr(vtProp.bstrVal, _T("08:00:27")) != 0){
						bFound = TRUE; break;
					}

					// release the current result object
					VariantClear(&vtProp);
					pclsObj->Release();
				}
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}

/*
Check vbox event log using WMI
*/
BOOL vbox_eventlogfile_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc);
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NTEventlogFile"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator && !bFound)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the FileName property
				hRes = pclsObj->Get(_T("FileName"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					// Do our comparaison
					if (StrCmpI(vtProp.bstrVal, _T("System")) == 0) {

						// Now, grab the Source property
						VariantClear(&vtProp);
						hRes = pclsObj->Get(_T("Sources"), 0, &vtProp, 0, 0);

						// Get the number of elements of our SAFEARRAY
						SAFEARRAY* saSources = vtProp.parray;
						LONG* pVals;
						HRESULT hr = SafeArrayAccessData(saSources, (VOID**)&pVals); // direct access to SA memory
						if (SUCCEEDED(hr)) {
							LONG lowerBound, upperBound;
							SafeArrayGetLBound(saSources, 1, &lowerBound);
							SafeArrayGetUBound(saSources, 1, &upperBound);
							LONG iLength = upperBound - lowerBound + 1;

							// Iteare over our array of BTSR
							TCHAR* bstrItem;
							for (LONG ix = 0; ix < iLength; ix++) {
								SafeArrayGetElement(saSources, &ix, (void *)&bstrItem);
								if (_tcsicmp(bstrItem, _T("vboxvideo")) == 0) {
									bFound = TRUE;
									break;
								}
							}
						}	
					}

					// release the current result object
					VariantClear(&vtProp);
					pclsObj->Release();
				}
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();

		}
	}

	return bFound;
}
