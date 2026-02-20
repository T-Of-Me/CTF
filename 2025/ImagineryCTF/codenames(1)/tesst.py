import os

WORDS_DIR = "words"

print(os.path.join(WORDS_DIR, "flag.txt"))   # language=flag
print(os.path.join(WORDS_DIR, "/flag.txt"))  # language=/flag
