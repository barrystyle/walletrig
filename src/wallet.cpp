// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"
#include "crypter.h"
#include "wallet.h"

using namespace std;

#include <boost/foreach.hpp>

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool CWallet::AddKey(const CKey& key)
{
    if (!CCryptoKeyStore::AddKey(key))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(key.GetPubKey(), key.GetPrivKey());
    return true;
}

bool CWallet::AddCryptedKey(const vector<unsigned char> &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::Unlock(const string& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;
    BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
    {
        if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
            return false;
        if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
            return false;
        if (CCryptoKeyStore::Unlock(vMasterKey))
            return true;
    }

    return false;
}

bool CWallet::UnlockVerbose(const string& strWalletPassphrase, int& errorLevel)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;
    BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
    {
        if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod)) {
            errorLevel = -1;
            return false;
        }
        if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey)) {
            errorLevel = -2;
            return false;
        }
        if (CCryptoKeyStore::Unlock(vMasterKey)) {
            errorLevel = 0;
            return true;
        }
    }

    errorLevel = -3;
    return false;
}

bool CWallet::PrintWalletDebug()
{
    if (!IsLocked())
        return false;

    int nCount = 0;
    CCrypter crypter;
    CKeyingMaterial vMasterKey;
    BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
    {
        std::string vchCryptedKey = PrintVectorToString(pMasterKey.second.vchCryptedKey);
        std::string vchSalt = PrintVectorToString(pMasterKey.second.vchSalt);
        unsigned int deriveIterations = pMasterKey.second.nDeriveIterations;
        unsigned int deriveMethod = pMasterKey.second.nDerivationMethod;

        printf("\n");
        printf("mapMasterKeys[%d]\n", nCount);
        printf("vchCryptedKey    %s\n", vchCryptedKey.c_str());
        printf("vchSalt          %s\n", vchSalt.c_str());
        printf("deriveIterations %d\n", deriveIterations);
        printf("deriveMethod     %d\n", deriveMethod);
    }

    return true;
}

bool CWallet::ChangeWalletPassphrase(const string& strOldWalletPassphrase, const string& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

bool CWallet::EncryptWallet(const string& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            pwalletdbEncryption->TxnBegin();
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1);
        }

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1);

            pwalletdbEncryption->Close();
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        Lock();
    }

    return true;
}

int CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return false;
    fFirstRunRet = false;
    int nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;

    return DB_LOAD_OK;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}
