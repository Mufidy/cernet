default:rmServer rmClient
	gcc dataBaseServer.c ds_lib_seu.c -o server -lsqlite3
	gcc send2Database.c ds_lib_seu.c -o client
server:rmServer
	gcc dataBaseServer.c ds_lib_seu.c -o server -lsqlite3
client:rmClient
	gcc send2Database.c ds_lib_seu.c -o client
rmServer:
	rm -f server
rmClient:
	rm -f client
