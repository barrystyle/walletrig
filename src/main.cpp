#include "crypter.h"
#include "db.h"
#include "listdb.h"
#include "uint256.h"
#include "util.h"
#include "wallet.h"

base58Prefix PUBKEY_ADDRESS = 0;
base58Prefix SCRIPT_ADDRESS = 5;
base58Prefix SECRET_KEY     = 128;

CWallet* pwalletMain = nullptr;

int main()
{
    printf("Loading wallet...\n");
    bool fFirstRun;
    pwalletMain = new CWallet("wallet.dat");
    int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK) {
        printf("error loading wallet.dat\n");
        return 0;
    }

    pwalletMain->PrintWalletDebug();

    //load pwlist
    printf("\nloading pwlist..\n");
    load_pwlist_db();

    //cracking
    int errorLevel;
    std::string passphrase;
    while (true) {
        next_password(passphrase);
        pwalletMain->UnlockVerbose(passphrase, errorLevel);
        if (errorLevel == 0)
            break;
    }
    printf("%s\n", passphrase.c_str());

    return 1;
}
