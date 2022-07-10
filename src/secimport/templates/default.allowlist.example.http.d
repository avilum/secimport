#!/usr/sbin/dtrace -Zs
/*
	This script generates a list of syscalls for a given program.
	It generates a filter for dscript.
	Line 17 can be replaced with the output of the following usage.

	USAGE:	sudo dtrace -s src/secimport/templates/default.allowlist.template.d -c "python -m http.server" # then CTRL+C
*/

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1

/* Non-Allowed syscalls probe - Kills the process */
/* Replace line 17 with the output of this script; */
syscall:::entry
/* /pid == $target && (probefunc != "__mac_syscall" && probefunc != "__pthread_canceled" && probefunc != "bind" && probefunc != "csrctl" && probefunc != "fgetattrlist" && probefunc != "getattrlist" && probefunc != "getrlimit" && probefunc != "listen" && probefunc != "pipe" && probefunc != "psynch_mutexwait" && probefunc != "sendmsg_nocancel" && probefunc != "shm_open" && probefunc != "sigreturn" && probefunc != "socketpair" && probefunc != "sysctlbyname" && probefunc != "__disable_threadsignal" && probefunc != "accept" && probefunc != "access" && probefunc != "bsdthread_create" && probefunc != "bsdthread_terminate" && probefunc != "connect_nocancel" && probefunc != "kqueue" && probefunc != "openat" && probefunc != "proc_info" && probefunc != "readlink" && probefunc != "recvfrom" && probefunc != "shutdown" && probefunc != "thread_selfid" && probefunc != "issetugid" && probefunc != "select_nocancel" && probefunc != "socket" && probefunc != "getsockname" && probefunc != "recvfrom_nocancel" && probefunc != "sendto" && probefunc != "gettimeofday" && probefunc != "kevent" && probefunc != "sysctl" && probefunc != "write" && probefunc != "sendto_nocancel" && probefunc != "fcntl_nocancel" && probefunc != "psynch_cvsignal" && probefunc != "psynch_cvwait" && probefunc != "setsockopt" && probefunc != "lstat64" && probefunc != "fstatfs64" && probefunc != "getdirentries64" && probefunc != "munmap" && probefunc != "read_nocancel" && probefunc != "poll" && probefunc != "getentropy" && probefunc != "open_nocancel" && probefunc != "close_nocancel" && probefunc != "madvise" && probefunc != "sigaction" && probefunc != "fcntl" && probefunc != "mprotect" && probefunc != "mmap" && probefunc != "open" && probefunc != "close" && probefunc != "lseek" && probefunc != "read" && probefunc != "fstat64" && probefunc != "ioctl" && probefunc != "stat64")/ */
/pid == $target && (0)/
{	
	printf("\t\tDetected invalid syscall %s, terminating process %d...\r\n", probefunc, pid);
	ustack();
	stop();
	printf("\t\tKILLING...\r\n");
	system("\t\tkill -9 %d", pid);
	printf("\t\tKILLED.\r\n");
	exit(-1);
}


/* Allowed syscalls probe */
syscall:::entry
/pid == $target/
{	
	@calls[basename(execname), "syscall", probefunc] = count();
	@syscalls[probefunc, "syscall"] = count();
}


dtrace:::END
{
	printf("\r\nsyscalls for %d:\r\n\r\n", $target);
	printf(" %-32s %-10s %-22s %8s\r\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\r\n", @calls);
	printf("\r\nAll syscalls:\r\n");
	printa(" %s\r\n", @syscalls);
	printf("\r\nWhitelist for you module:\r\n\r\n");
	printa("probefunc != \"%s\" && ", @syscalls);
	printf("\r\n\r\nGo to src/secimport/templates/default.allowlist.template.d and modify you whitelist probe.\r\n\r\n");
	printf("\r\nDone.\r\n")
}