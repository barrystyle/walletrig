#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

#include <openssl/rand.h>

#include "uint256.h"

#include "boost/date_time/posix_time/posix_time.hpp"

#define _vsnprintf(a,b,c,d) vsnprintf(a,b,c,d)

typedef unsigned int base58Prefix;

extern base58Prefix PUBKEY_ADDRESS;
extern base58Prefix SCRIPT_ADDRESS;
extern base58Prefix SECRET_KEY;

inline int64 GetPerformanceCounter()
{
    int64 nCounter = 0;
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = t.tv_sec * 1000000 + t.tv_usec;
    return nCounter;
}

inline int64 GetTimeMillis()
{
    return (boost::posix_time::ptime(boost::posix_time::microsec_clock::universal_time()) -
            boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
}

inline std::string DateTimeStrFormat(const char* pszFormat, int64 nTime)
{
    time_t n = nTime; 
    struct tm* ptmTime = gmtime(&n);
    char pszTime[200];
    strftime(pszTime, sizeof(pszTime), pszFormat, ptmTime);
    return pszTime;
}

std::string GetDataDir();
std::string strprintf(const std::string &format, ...);
std::vector<unsigned char> ParseHex(const char* psz);
std::vector<unsigned char> ParseHex(const std::string& str);
std::string PrintVectorToString(std::vector<unsigned char> inVec);

int64 GetTime();
void SetMockTime(int64 nMockTimeIn);

void RandAddSeedPerfmon();

#endif // UTIL_H
