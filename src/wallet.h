// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include "key.h"
#include "keystore.h"
#include "serialize.h"

#include <openssl/rand.h>

class CReserveKey;
class CWalletDB;

// A CWallet is an extension of a keystore, which also maintains a set of
// transactions and balances, and provides the ability to create new
// transactions
class CWallet : public CCryptoKeyStore
{
private:
    CWalletDB *pwalletdbEncryption;

public:
    bool fFileBacked;
    std::string strWalletFile;

    std::set<int64> setKeyPool;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CWallet()
    {
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
    }

    CWallet(std::string strWalletFileIn)
    {
        strWalletFile = strWalletFileIn;
        fFileBacked = true;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
    }

    std::vector<uint256> vWalletUpdated;

    std::map<uint256, int> mapRequestCount;

    std::map<CBitcoinAddress, std::string> mapAddressBook;

    // keystore implementation
    // Adds a key to the store, and saves it to disk.
    bool AddKey(const CKey& key);
    // Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key) { return CCryptoKeyStore::AddKey(key); }
    // Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const std::vector<unsigned char> &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    // Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const std::vector<unsigned char> &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret) { return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret); }

    bool Unlock(const std::string& strWalletPassphrase);
    bool UnlockVerbose(const std::string& strWalletPassphrase, int& errorLevel);
    bool ChangeWalletPassphrase(const std::string& strOldWalletPassphrase, const std::string& strNewWalletPassphrase);
    bool EncryptWallet(const std::string& strWalletPassphrase);
    bool PrintWalletDebug();

    int LoadWallet(bool& fFirstRunRet);

    int GetKeyPoolSize()
    {
        return setKeyPool.size();
    }
};




//
// Private key that includes an expiration date in case it never gets used.
//
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64 nTimeCreated;
    int64 nTimeExpires;
    std::string strComment;
    //// todo: add something to note what created it (user, getnewaddress, change)
    ////   maybe should have a map<string, string> property map

    CWalletKey(int64 nExpires=0)
    {
        nTimeCreated = (nExpires ? GetTime() : 0);
        nTimeExpires = nExpires;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(strComment);
    )
};






//
// Account information.
// Stored in wallet with key "acc"+string account name
//
class CAccount
{
public:
    std::vector<unsigned char> vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey.clear();
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    )
};

bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

#endif
