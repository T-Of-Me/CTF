import re
from timeout_decorator import timeout

@timeout(2)
def search(r, s):
    return re.match(r, s)