import threading

import time

fin = ([False,], "warbler")


def b(finish, word):
    print(finish)
    while finish[0] == False:
        print(word)
        time.sleep(1)


def a(finish, word):
    time.sleep(5)
    finish[0] = True

print(fin)
tha = threading.Thread(target=a, args=fin)
thb = threading.Thread(target=b, args=fin)

tha.start()
thb.start()


