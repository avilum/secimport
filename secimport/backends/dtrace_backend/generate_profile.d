#!/usr/sbin/dtrace -Zs
/*
	This script generates a list of syscalls for a given program.
	It generates a filter for dscript.
	The first probe can be replaced with the output of the following usage.

	USAGE:	sudo dtrace -s secimport/templates/generate_profile.d -c "python -m http.server" # then CTRL+C
*/

#pragma D option quiet
#pragma D option switchrate=1

/* Trace syscalls probe */
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
