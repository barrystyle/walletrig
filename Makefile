CC = g++
CPPFLAGS = -O2 -I./src -I./src/crypto -lssl -lcrypto -Wno-deprecated-declarations -ldb_cxx

OBJ =   src/base58.o              \
	src/crypter.o             \
	src/db.o                  \
	src/listdb.o              \
	src/keystore.o            \
	src/main.o                \
	src/util.o                \
	src/wallet.o              \
	src/crypto/ripemd160.o    \
	src/crypto/sha256.o

%.o: %.cpp
	$(CC) -c -o $@ $< $(CPPFLAGS)

walletrig: $(OBJ)
	$(CC) -o $@ $^ $(CPPFLAGS)
clean:
	rm -f src/*.o
	rm -f src/*/*.o
