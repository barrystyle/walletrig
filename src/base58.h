// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include "hash.h"
#include "util.h"

#include <string>
#include <vector>

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch);
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);
std::string EncodeBase58(const std::vector<unsigned char>& vch);
bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet);
std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn);
bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet);
bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet);

// Base class for all base58-encoded data
class CBase58Data
{
protected:
    // the version byte
    unsigned char nVersion;

    // the actually encoded data
    std::vector<unsigned char> vchData;

    CBase58Data()
    {
        nVersion = 0;
        vchData.clear();
    }

    ~CBase58Data()
    {
        // zero the memory, as it may contain sensitive data
        if (!vchData.empty())
            memset(&vchData[0], 0, vchData.size());
    }

    void SetData(int nVersionIn, const void* pdata, size_t nSize)
    {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (!vchData.empty())
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(nVersionIn, (void*)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char* psz)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty())
        {
            vchData.clear();
            nVersion = 0;
            return false;
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());
        memset(&vchTemp[0], 0, vchTemp.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch(1, nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (nVersion < b58.nVersion) return -1;
        if (nVersion > b58.nVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

// base58-encoded bitcoin addresses
// Addresses have version 0 or 111 (testnet)
// The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key
class CBitcoinAddress : public CBase58Data
{
public:
    bool SetHash160(const uint160& hash160)
    {
        SetData(PUBKEY_ADDRESS, &hash160, 20);
        return true;
    }

    bool SetPubKey(const std::vector<unsigned char>& vchPubKey)
    {
        return SetHash160(Hash160(vchPubKey));
    }

    bool IsValid() const
    {
        int nExpectedSize = 20;
        return nVersion == PUBKEY_ADDRESS &&
               vchData.size() == nExpectedSize;
    }

    CBitcoinAddress()
    {
    }

    CBitcoinAddress(uint160 hash160In)
    {
        SetHash160(hash160In);
    }

    CBitcoinAddress(const std::vector<unsigned char>& vchPubKey)
    {
        SetPubKey(vchPubKey);
    }

    CBitcoinAddress(const std::string& strAddress)
    {
        SetString(strAddress);
    }

    CBitcoinAddress(const char* pszAddress)
    {
        SetString(pszAddress);
    }

    uint160 GetHash160() const
    {
        assert(vchData.size() == 20);
        uint160 hash160;
        memcpy(&hash160, &vchData[0], 20);
        return hash160;
    }
};

#endif
