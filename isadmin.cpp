#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>

#pragma comment(lib,"advapi32.lib")

BOOL IsAdmin(VOID) {
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup);
    if(b) {
        if (!CheckTokenMembership( NULL, AdministratorsGroup, &b)) {
            b = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }
    return(b);
}

int main(int argc, char const *argv[])
{
	std::cout << IsAdmin() << std::endl;
	return 0;
}
