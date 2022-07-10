#!/usr/sbin/dtrace -Zs
/*
	This script generates a list of syscalls for a given program.
	It generates a filter for dscript.
	Line 13 can be replaced with your generated filter to run your app.

	USAGE:	sudo dtrace -s src/secimport/templates/default.allowlist.template.d -c "python -m http.server"
*/

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1

/* Non-Allowed syscalls probe - Kills the process */
/* Replace "0" with the output of this script; */
syscall:::entry
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