include ../Makefile.inc

ARFLAGS=rcs

LIB = cmd
OBJS =	cmd_auth.o cmd_cwd.o cmd_delete.o cmd_feat.o \
	cmd_list.o cmd_mdtm.o cmd_mkdir.o \
	cmd_passive.o cmd_pbsz.o cmd_prot.o cmd_pwd.o \
	cmd_quit.o cmd_retr.o cmd_rmdir.o cmd_rnfr.o \
	cmd_rnto.o cmd_site_chmod.o cmd_site_mdfive.o \
	cmd_size.o cmd_stat.o cmd_statfile.o cmd_store.o  \
	cmd_user.o cmd_pass.o cmd_opts.o

CFLAGS+= -I../include

all: lib$(LIB).a

lib$(LIB).a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f core */*~ *~ */*.o */*.po *.a *.o *.so*

