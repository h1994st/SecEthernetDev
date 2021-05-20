
OPENSSLDIR = /usr/local/ssl
INCLUDE = $(OPENSSLDIR)/include
LIB = $(OPENSSLDIR)/lib
FLAGS = -Wall
CC = gcc

all: libtesla.so tesla_test sample_server sample_client

LIB_OBJ = tesla.o NTP.o client.o sender.o octet_stream.o hashtable.o
CLIENT_OBJ = tesla.o NTP.o client.o octet_stream.o hashtable.o

tesla_test: tesla_test.o libtesla.so
	$(CC) -ggdb -I$(INCLUDE) -L$(LIB) -L. -o tesla_test tesla_test.o -ltesla -lcrypto $(EX_LIBS)

sample_server: sample_server.o sample.o libtesla.so
	$(CC) -ggdb -I$(INCLUDE) -L. -L$(LIB) -o sample_server sample.o sample_server.o -ltesla -lcrypto

sample_client: sample_client.o sample.o libtesla.so
	$(CC) -ggdb -I$(INCLUDE) -L. -L$(LIB) -o sample_client sample_client.o sample.o -ltesla -lcrypto

libtesla.so: $(LIB_OBJ)
	$(CC) -shared -I$(INCLUDE) -o libtesla.so $(LIB_OBJ) -L$(OPENSSLDIR) -lcrypt $(EX_LIBS)

install: libtesla.so
	cp libtesla.so  /usr/lib/libtesla.so

libtesla.a: $(LIB_OBJ)
	ar rcs libtesla.a $(LIB_OBJ)

libtesla_client.a: $(CLIENT_OBJ)
	ar rcs libtesla_client.a $(CLIENT_OBJ)

libtesla_client.so: $(CLIENT_OBJ)
	$(CC) -shared -I$(INCLUDE) -o libtesla_client.so $(CLIENT_OBJ) -L$(OPENSSLDIR) -lcrypt $(EX_LIBS)

%.o: %.c
	$(CC) $(FLAGS) -I$(INCLUDE) -c $?

tar:
	tar -cvzf tesla.taz *.c *.h README Makefile *.pem

clean:
	rm -f *.o
	rm -f *.exe
	rm -f *.a
	rm -f *.so
	rm -f *~
	rm -f sample_server
	rm -f sample_client
	rm -f tesla_test
