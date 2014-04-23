#!/bin/sh

#
# Add the following line to /etc/rc.conf to enable SmbFTPD:
# smbftpd_enable (bool):	Set to "NO" by default.
#				Set it to "YES" to enable SmbFTPD.

name="smbftpd"
command="/home/andy/wnc/fakeroot/sbin/smbftpd"
smbftpd_enable=${smbftpd_enable-"NO"}
smbftpd_flags=${smbftpd_flags-"-D"}

OSRelease=`sysctl -n kern.osrelease`
case $OSRelease in
[567].*)
	. /etc/rc.subr

	rcvar=`set_rcvar`
	load_rc_config $name
	run_rc_command "$1"
	;;
*)
	. /etc/rc.conf
	case $1 in
	start)
		case "$smbftpd_enable" in
		[Nn][Oo])
			echo "The \"smbftpd_enable\" must be set to \"Yes\" in rc.conf"
			exit 1
			;;
		esac
		echo "Starting $name"
		$command $smbftpd_flags
		;;
	stop)
		echo "Stopping $name"
		killall $name
		;;
	restart)
		$0 stop
		sleep 1
		$0 start
		;;
	*)
		echo "Usages: $0 [start|stop|restart]"
		;;
	esac
	;;
esac		
