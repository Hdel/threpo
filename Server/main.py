import DatabaseThread
import DatabaseUtils
import ServerThread

# ssl_server = ServerThread.SSLServer()
# ssl_server.start()

# print("done")

# db_thread = DatabaseThread.DatabaseThread()
# db_thread.start()
# switch_thread = SwitchCheckHandler()
# switch_thread.start()

DatabaseUtils.database_init()

server = ServerThread.SocketServer()
server.start()
server.join()
print("done")


# ssl_server.join()
