all:
	$(CC) -Wall -Wextra -O2 -s -static $(CFLAGS) \
		main.c wudparts.c rijndael.c sha1.c -o wud2app
install:
	@echo "nothing to install"
clean:
	@rm -f wud2app
