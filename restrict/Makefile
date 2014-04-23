include ../Makefile.inc

ARFLAGS=rcs

LIB =	restrict
OBJS =	tcp_wrapper.o throttle.o smbmode.o chroot.o shell.o nologin.o \
	iptrack.o

CFLAGS+= -I../include

all: lib$(LIB).a

lib$(LIB).a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f core */*~ *~ */*.o */*.po *.a *.o *.so*

