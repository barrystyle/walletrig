#include "crypter.h"
#include "db.h"
#include "listdb.h"
#include "uint256.h"
#include "util.h"
#include "wallet.h"

#include <thread>

int total_threads = 12;
base58Prefix PUBKEY_ADDRESS = 48;
base58Prefix SCRIPT_ADDRESS = 5;
base58Prefix SECRET_KEY     = 176;

bool quitAll = false;
CWallet* pwalletMain = nullptr;

static void worker_thread(int id, size_t st)
{
    size_t stn = 0;
    int errorLevel;
    std::string passphrase;
    while (!quitAll) {
        printf("\033[%d;0H [thread%02d] %d / %d", id+1, id, (int) stn, (int) (total_size() / total_threads));
        password_at(st, passphrase);
        if (pwalletMain->UnlockVerbose(passphrase, errorLevel)) {
            quitAll = true;
            printf("\n\nfound passphrase was '%s'\n\n", passphrase.c_str());
            return;
        }
        ++st;
        ++stn;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("please specify wallet path/file\n");
        return 0;
    }

    //init vars
    printf("Loading wallet...\n");
    bool fFirstRun;
    pwalletMain = new CWallet(argv[1]);
    int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK) {
        printf("error loading wallet.dat\n");
        return 0;
    }

    pwalletMain->PrintWalletDebug();

    //load pwlist
    printf("\nloading pwlist..\n");
    load_pwlist_db();
    sleep(3);

    //cracking
    printf("\033[2J\033[1;1H");
    size_t total_list = total_size();
    std::vector<std::thread> worker_threads;
    for (int i=0; i<total_threads; i++) {
        size_t st = total_list / (size_t) total_threads;
        worker_threads.push_back(std::thread(worker_thread, i, i * st));
    }

    for (int i=0; i<total_threads; i++) {
        if (worker_threads[i].joinable()) worker_threads[i].join();
    }

    return 1;
}
