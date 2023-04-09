#!/usr/sbin/dtrace -Zs

#pragma D option quiet
#pragma D option switchrate=1

/* Non-Allowed syscalls probe - Kills the process */
/* Replace line 17 with the output of this script; */
/* syscall:::entry
/pid == $target
 && (###SYSCALL_FILTER###)
 /
{
	printf("\t\tDetected invalid syscall %s, terminating process %d...\r\n", probefunc, pid);
	ustack();
	stop();
	printf("\t\tKILLING...\r\n");
	system("\t\tkill -9 %d", pid);
	printf("\t\tKILLED.\r\n");
	exit(-1);
} */

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
	printa("- %s\r\n", @syscalls);
	printf("\r\n Generated syscalls (yaml profile):\r\n");
	printf("    destructive: true\r\n    syscall_allowlist:\r\n");
	printa("        - %s\r\n", @syscalls);
	printf("\r\nDone.\r\n")
}
