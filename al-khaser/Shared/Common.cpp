#include "Common.h"
#include "Utils.h"
#include "log.h"
#include <exception>

#include "md5.h"  
#include <iostream>  
#include <string>

using namespace std;

void md5(unsigned char *inBuf, unsigned int inLen, char *outBuf, unsigned int inSize)
{
	MD5_CTX mdContext;
	
	MD5Init(&mdContext);
	//MD5Update(&mdContext, (unsigned char*)const_cast<char*>(strPlain.c_str()), iLen);
	MD5Update(&mdContext, const_cast<unsigned char*>(inBuf), inLen);
	MD5Final(&mdContext);

	for (int i = 0; i < 16; i++) {
		sprintf_s(&outBuf[i * 2], inSize, "%02X", mdContext.digest[i]);
	}

	return;
}

VOID print_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 12);
	_tprintf(TEXT("[ BAD  ]\n"));
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID print_not_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 10);
	_tprintf(TEXT("[ GOOD ]\n"));
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID print_category(TCHAR* text)
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);  
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 13);
	_tprintf(TEXT("\n-------------------------[%s]-------------------------\n"), text);
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID print_results(int result, TCHAR* szMsg)
{
	_tprintf(TEXT("[*] %s"), szMsg);

	/* align the result according to the length of the text */
	int spaces_to_padd = 95 - _tcslen(szMsg);
	while (spaces_to_padd > 0) {
		_tprintf(TEXT(" "));
		spaces_to_padd--;
	}
	
	if (result == TRUE)
		print_detected();
	else
		print_not_detected();

	/* log to file*/
	TCHAR buffer[256] = _T("");
	_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("[*] %s -> %d"), szMsg, result);


	UINT inLen = _tcslen(szMsg) * 2;
	char szMD5[64] = "";

	md5((unsigned char*)szMsg, inLen, &szMD5[0], 64);

	TCHAR new_name[256] = _T("");
	TCHAR * pName = ascii_to_wide_str(szMD5);
	_stprintf_s(new_name, sizeof(new_name) / sizeof(TCHAR), _T(".\\config\\%s_%d"), pName, result);

	
	HANDLE hFile = CreateFile(new_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
	DWORD dwWrite = 0;
	WriteFile(hFile, &buffer, lstrlen(buffer), &dwWrite, NULL);
	CloseHandle(hFile);

	
	
	LOG_PRINT(buffer);
}

VOID exec_check(int(*callback)(), TCHAR* szMsg) 
{
	/* Call our check */
	int result = callback();

	/* Print / Log the result */
	if (szMsg)
		print_results(result, szMsg);
}

VOID resize_console_window()
{
	// Change the window title:
	SetConsoleTitle(_T("Al-Khaser - by Lord Noteworthy"));

	// Get console window handle
	HWND wh = GetConsoleWindow();

	// Move window to required position
	MoveWindow(wh, 100, 100, 900, 900, TRUE);
}


VOID print_os()
{
	TCHAR szOS[MAX_PATH] = _T("");
	if (GetOSDisplayString(szOS))
	{
		_tcscpy_s(szOS, MAX_PATH, szOS);
		_tprintf(_T("\nOS: %s\n"), szOS);
	}
}

VOID print_last_error(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(			
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 

    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 

	_tprintf((LPCTSTR)lpDisplayBuf); 


    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

TCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr)
{

	/* Get the required size */
	CONST INT iSizeRequired = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, NULL, 0);

	TCHAR *lpWideCharStr = (TCHAR*)MALLOC(iSizeRequired * sizeof(TCHAR));

	/* Do the conversion */
	INT iNumChars =  MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, lpWideCharStr, iSizeRequired);

	return lpWideCharStr;
}

CHAR* wide_str_to_multibyte (TCHAR* lpWideStr)
{
	errno_t status;
	int *pRetValue = NULL;
	CHAR *mbchar = NULL;
	size_t sizeInBytes = 0;
	
	status = wctomb_s(pRetValue, mbchar, sizeInBytes, *lpWideStr);
	return mbchar;
}
