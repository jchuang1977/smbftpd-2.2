include ../Makefile.inc

ARFLAGS=rcs

LIB = ftpssl
OBJS =	dataconn.o init.o io.o session.o

CFLAGS+= -I../include

all: lib$(LIB).a

lib$(LIB).a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f core */*~ *~ */*.o */*.po *.a *.o *.so*

