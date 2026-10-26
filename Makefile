CC      = gcc
CFLAGS  = -Wall -Wextra -g -pthread
LIBS    = -lsqlite3 -lcrypt
SERVER_SRC = server.c net.c session.c db.c auth.c audit.c accounts.c staff.c money.c loans.c
HDRS = db.h net.h session.h common.h handlers.h auth.h audit.h accounts.h money.h

all: bank_server bank_client

bank_server: $(SERVER_SRC) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC) $(LIBS)

bank_client: client.c
	$(CC) $(CFLAGS) -o $@ client.c

clean:
	rm -f bank_server bank_client bank.db* bank.lock
