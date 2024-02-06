import psutil
from os import getpid
# print(f'mem usage in {__file__}', memory_usage_psutil())
def memory_usage_psutil():
    # return the memory usage in kb
    process = psutil.Process(getpid())
    mem = process.memory_info().rss / float(2 ** 10)
    return mem