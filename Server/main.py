import DatabaseThread
import DatabaseUtils
import ServerThread

# ssl_server.start()

# print("done")

# db_thread.start()
# switch_thread.start()
from SwitchCheckHandler import SwitchCheckHandler

DatabaseUtils.database_init()

ssl_server = ServerThread.SSLServer()
server = ServerThread.ServerMain()
db_thread = DatabaseThread.DatabaseThread()
switch_thread = SwitchCheckHandler()

ssl_server.start()
server.start()
db_thread.start()
switch_thread.start()
