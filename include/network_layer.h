#pragma once
/*
 * ================================================================
 *  CryptVault — network_layer.h
 *  Cross-platform socket + thread abstraction
 *
 *  Hides ALL platform differences so p2p_node.cpp
 *  compiles identically on Windows and Linux.
 *
 *  Windows compile:  g++ ... -lws2_32
 *  Linux compile:    g++ ... -lpthread
 * ================================================================
 */

#include <string>
#include <iostream>
#include <cstring>
using namespace std;

// ── SOCKET ABSTRACTION ────────────────────────────────────────
#ifdef _WIN32
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    typedef SOCKET socket_t;
    #define INVALID_SOCK  INVALID_SOCKET
    #define SOCK_ERR      SOCKET_ERROR

    inline void sockInit() {
        WSADATA w;
        int r = WSAStartup(MAKEWORD(2,2), &w);
        if (r != 0)
            cerr << "  [NET] WSAStartup failed: " << r << endl;
    }
    inline void sockCleanup()     { WSACleanup(); }
    inline void sockClose(socket_t s) { closesocket(s); }
    inline int  sockErrno()       { return WSAGetLastError(); }
    inline bool sockValid(socket_t s) { return s != INVALID_SOCKET; }

    // Windows sleep in milliseconds
    inline void sleepMs(int ms)   { Sleep(ms); }

#else
    // Linux / macOS
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>

    typedef int socket_t;
    #define INVALID_SOCK  (-1)
    #define SOCK_ERR      (-1)

    inline void sockInit()        {}
    inline void sockCleanup()     {}
    inline void sockClose(socket_t s) { close(s); }
    inline int  sockErrno()       { return errno; }
    inline bool sockValid(socket_t s) { return s >= 0; }

    inline void sleepMs(int ms)   {
        struct timespec ts;
        ts.tv_sec  = ms / 1000;
        ts.tv_nsec = (ms % 1000) * 1000000L;
        nanosleep(&ts, nullptr);
    }
#endif

// ── SOCKET HELPERS ────────────────────────────────────────────

// Set socket to non-blocking mode
inline void setNonBlocking(socket_t s, bool nonBlocking) {
#ifdef _WIN32
    u_long mode = nonBlocking ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (nonBlocking)
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
    else
        fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

// Set socket option SO_REUSEADDR
inline void setReuseAddr(socket_t s) {
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&opt, sizeof(opt));
}

// Reliable send — keeps sending until all bytes are sent
inline bool sendAll(socket_t s, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Reliable recv — keeps reading until all bytes received
inline bool recvAll(socket_t s, char* buf, int len) {
    int received = 0;
    while (received < len) {
        int r = recv(s, buf + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

// ── THREAD ABSTRACTION ───────────────────────────────────────
#ifdef _WIN32
    typedef HANDLE thread_t;

    template<typename Fn, typename Arg>
    thread_t startThread(Fn fn, Arg* arg) {
        return CreateThread(
            NULL, 0,
            (LPTHREAD_START_ROUTINE)fn,
            (LPVOID)arg, 0, NULL
        );
    }
    inline void joinThread(thread_t t) {
        WaitForSingleObject(t, INFINITE);
        CloseHandle(t);
    }
#else
    #include <pthread.h>
    typedef pthread_t thread_t;

    template<typename Fn, typename Arg>
    thread_t startThread(Fn fn, Arg* arg) {
        pthread_t t;
        pthread_create(&t, NULL, (void*(*)(void*))fn, (void*)arg);
        pthread_detach(t);
        return t;
    }
    inline void joinThread(thread_t t) {
        pthread_join(t, nullptr);
    }
#endif

// ── MUTEX ABSTRACTION ────────────────────────────────────────
#ifdef _WIN32
    typedef CRITICAL_SECTION mutex_t;
    inline void mutexInit(mutex_t& m)    { InitializeCriticalSection(&m); }
    inline void mutexLock(mutex_t& m)    { EnterCriticalSection(&m); }
    inline void mutexUnlock(mutex_t& m)  { LeaveCriticalSection(&m); }
    inline void mutexDestroy(mutex_t& m) { DeleteCriticalSection(&m); }
#else
    typedef pthread_mutex_t mutex_t;
    inline void mutexInit(mutex_t& m)    { pthread_mutex_init(&m, nullptr); }
    inline void mutexLock(mutex_t& m)    { pthread_mutex_lock(&m); }
    inline void mutexUnlock(mutex_t& m)  { pthread_mutex_unlock(&m); }
    inline void mutexDestroy(mutex_t& m) { pthread_mutex_destroy(&m); }
#endif

// RAII lock guard — automatically releases on scope exit
struct LockGuard {
    mutex_t& m;
    LockGuard(mutex_t& mx) : m(mx) { mutexLock(m); }
    ~LockGuard()                    { mutexUnlock(m); }
};
