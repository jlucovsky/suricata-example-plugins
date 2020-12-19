SRCS := 	template.c

# This needs to point to the Suricata includes.
CFLAGS += -I /home/jlucovsky/src/jal/4126/src
CPPFLAGS +=	-I/usr/local/include/suricata -I/usr/include/lua5.1 -I /home/jlucovsky/src/jal/4126/src

CPPFLAGS +=	-DSURICATA_PLUGIN -I.

#CFLAGS="-I/home/jlucovsky/src/jal/4126/src"  CPPFLAGS="-I/home/jlucovsky/src/jal/4126/src -I/usr/include/lua5.1" make

all:
	$(CC) -ggdb3 -fPIC $(CPPFLAGS) -o eve-filetype.so -shared $(SRCS)

clean:
	rm -f *.so *~
