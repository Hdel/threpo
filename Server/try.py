import threading

pool_dict = {}


class AgentHandlerThread(threading.Thread):
    def __init__(self, pool_dict):
        threading.Thread.__init__(self)
        self.pool_dict = pool_dict

    def run(self):
        self.pool_dict.update({"a": "aa"})


print(pool_dict)
a = AgentHandlerThread(pool_dict)
a.start()
print(pool_dict)