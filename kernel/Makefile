CFLAGS = -D__KERNEL__ -march=i586 -DMODULE -DMODVERSIONS -include /usr/src/linux/include/linux/modversions.h -I/usr/src/linux/include -Wall -O2 -fomit-frame-pointer


ipt_ULOG.o: ipt_ULOG.c Makefile
	gcc $(CFLAGS) -c ipt_ULOG.c

clean: 
	rm -f *.o
