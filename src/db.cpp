// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"

#include <stdexcept>

#include <boost/foreach.hpp>
#include <filesystem>

using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;
uint64 nAccountingEntryNumber = 0;



//
// CDB
//

static bool fDbEnvInit = false;
DbEnv dbenv(0);
static map<string, int> mapFileUseCount;
static map<string, Db*> mapDb;

static void EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    try
    {
        dbenv.close(0);
    }
    catch (const DbException& e)
    {
        printf("EnvShutdown exception: %s (%d)\n", e.what(), e.get_errno());
    }
    DbEnv(0).remove(GetDataDir().c_str(), 0);
}

class CDBInit
{
public:
    CDBInit()
    {
    }
    ~CDBInit()
    {
        EnvShutdown();
    }
}
instance_of_cdbinit;


CDB::CDB(const char* pszFile, const char* pszMode) : pdb(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        if (!fDbEnvInit)
        {
            string strDataDir = GetDataDir();
            string strLogDir = strDataDir + "/database";
            std::filesystem::create_directory(strLogDir.c_str());
            string strErrorFile = strDataDir + "/db.log";
            printf("dbenv.open strLogDir=%s strErrorFile=%s\n", strLogDir.c_str(), strErrorFile.c_str());

            dbenv.set_lg_dir(strLogDir.c_str());
            dbenv.set_lg_max(10000000);
            dbenv.set_lk_max_locks(10000);
            dbenv.set_lk_max_objects(10000);
            dbenv.set_errfile(fopen(strErrorFile.c_str(), "a")); /// debug
            dbenv.set_flags(DB_AUTO_COMMIT, 1);
            ret = dbenv.open(strDataDir.c_str(),
                             DB_CREATE     |
                             DB_INIT_LOCK  |
                             DB_INIT_LOG   |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN   |
                             DB_THREAD     |
                             DB_RECOVER,
                             S_IRUSR | S_IWUSR);
            if (ret > 0)
                throw runtime_error(strprintf("CDB() : error %d opening database environment", ret));
            fDbEnvInit = true;
        }

        strFile = pszFile;
        ++mapFileUseCount[strFile];
        pdb = mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(&dbenv, 0);

            ret = pdb->open(NULL,      // Txn pointer
                            pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret > 0)
            {
                delete pdb;
                pdb = NULL;
                    --mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(VERSION);
                fReadOnly = fTmp;
            }

            mapDb[strFile] = pdb;
        }
    }
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (!vTxn.empty())
        vTxn.front()->abort();
    vTxn.clear();
    pdb = NULL;

    string strDataDir = GetDataDir();
    string strLogDir = strDataDir + "/database";
    std::filesystem::remove_all(strLogDir.c_str());
    string strErrorFile = strDataDir + "/db.log";
    std::filesystem::remove(strErrorFile);
}

void static CloseDb(const string& strFile)
{
    {
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

void DBFlush(bool fShutdown)
{
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("DBFlush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    {
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            printf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                dbenv.txn_checkpoint(0, 0, 0);
                printf("%s flush\n", strFile.c_str());
                dbenv.lsn_reset(strFile.c_str(), 0);
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
            {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                EnvShutdown();
            }
        }
    }
}










//
// CWalletDB
//

int CWalletDB::LoadWallet(CWallet* pwallet)
{
    int nFileVersion = 0;
    bool fIsEncrypted = false;

    ///////////////////////////////////////////////////
    std::map<std::string, unsigned int> wallet_entries;
    ///////////////////////////////////////////////////

    {
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return DB_CORRUPT;

        while (true)
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return DB_CORRUPT;

            // Unserialize
            // Taking advantage of the fact that pair serialization
            // is just the two items serialized one after the other
            string strType;
            ssKey >> strType;

            ///////////////////////////////////
            if (!wallet_entries.count(strType))
                wallet_entries[strType] = 1;
            else
                ++wallet_entries[strType];
            ///////////////////////////////////

            if (strType == "name")
            {
                string strAddress;
                ssKey >> strAddress;
                ssValue >> pwallet->mapAddressBook[strAddress];
            }

            else if (strType == "acentry")
            {
                string strAccount;
                ssKey >> strAccount;
                uint64 nNumber;
                ssKey >> nNumber;
                if (nNumber > nAccountingEntryNumber)
                    nAccountingEntryNumber = nNumber;
            }

            else if (strType == "key" || strType == "wkey")
            {
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                CKey key;
                if (strType == "key")
                {
                    CPrivKey pkey;
                    ssValue >> pkey;
                    key.SetPrivKey(pkey);
                }
                else
                {
                    CWalletKey wkey;
                    ssValue >> wkey;
                    key.SetPrivKey(wkey.vchPrivKey);
                }

                if (!pwallet->LoadKey(key))
                    return DB_CORRUPT;
            }

            else if (strType == "mkey")
            {
                unsigned int nID;
                ssKey >> nID;
                CMasterKey kMasterKey;
                ssValue >> kMasterKey;
                if(pwallet->mapMasterKeys.count(nID) != 0)
                    return DB_CORRUPT;
                pwallet->mapMasterKeys[nID] = kMasterKey;
                if (pwallet->nMasterKeyMaxID < nID)
                    pwallet->nMasterKeyMaxID = nID;
            }

            else if (strType == "ckey")
            {
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                vector<unsigned char> vchPrivKey;
                ssValue >> vchPrivKey;
                if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
                    return DB_CORRUPT;
                fIsEncrypted = true;
            }

            else if (strType == "pool")
            {
                int64 nIndex;
                ssKey >> nIndex;
                pwallet->setKeyPool.insert(nIndex);
            }

            else if (strType == "version")
            {
                ssValue >> nFileVersion;
                if (nFileVersion == 10300)
                    nFileVersion = 300;
            }
        }

        pcursor->close();
    }

    printf("nFileVersion = %d\n", nFileVersion);
    printf("fIsEncrypted = %s\n", fIsEncrypted ? "true" : "false");

    /////////////////////////////////////////////////////////////////
    printf("\n");
    for (const auto& pair : wallet_entries) {
        printf("%s - %d entries\n", pair.first.c_str(), pair.second);
    }
    /////////////////////////////////////////////////////////////////

    return DB_LOAD_OK;
}
