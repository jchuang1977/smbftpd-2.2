include ../Makefile.inc

ARFLAGS=rcs

LIB = auth
OBJS = auth.o unix.o pam.o mysql.o pgsql.o text.o

CFLAGS+= -I../include

all: lib$(LIB).a

lib$(LIB).a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f core */*~ *~ */*.o */*.po *.a *.o *.so*

