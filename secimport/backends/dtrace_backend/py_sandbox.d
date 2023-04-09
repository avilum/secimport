#!/usr/sbin/dtrace -Zs

/*
Examples based on:
	https://docs.oracle.com/cd/E18752_01/html/819-5488/gcfpz.html
	https://opensource.apple.com/source/dtrace/dtrace-147/DTTk/dtruss.auto.html
	https://www.brendangregg.com/Articles/FreeBSDwiki_DTrace_Tutorial_2014.pdf
	https://docs.oracle.com/en/operating-systems/solaris/oracle-solaris/11.4/dtrace-guide/arrays-dtrace.html
*/

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1

/* A depth matrix for modules by name, maps each module (string) to the stack depth (int) at which it entered. */
int depth_matrix[string];
self int depth;
self int sandbox_module_reached;

string current_module_str;
string previous_module_str;
/*
inline string RED       = "33[31;1m";
inline string BLUE      = "33[34;1m";
inline string GREEN     = "33[32;1m";
inline string VIOLET    = "33[35;1m";
inline string OFF       = "33[0m";
*/

dtrace:::BEGIN
{
	printf("%s %6s %10s  %16s:%-4s %-8s -- %s\n", "C", "PID", "DELTA(us)",
	    "FILE", "LINE", "TYPE", "FUNC");
}

python*:::function-entry,
python*:::function-return
/self->last == 0/
{
	self->last = timestamp;
}

python*:::function-entry
{
	this->delta = (timestamp - self->last) / 1000;

	/* Memoizing the previous module and current module */
	_current_module_str = stringof(copyinstr(arg0)));
	previous_module_str = stringof(current_module_str);
	current_module_str =  _current_module_str;

	/* Saving the stack depth for each module, assuming interpreter with GIL will run line-by-line. */
	if (depth_matrix[current_module_str] == 0){
		depth_matrix[current_module_str] = self->depth;
	}

	printf("\r\n%d %6d %10d  %16s:%-4d %-8s %*s-> %s", cpu, pid, this->delta,
	    current_module_str, arg2, "func", self->depth * 4, "",
	    copyinstr(arg1));
	self->depth++;
	self->last = timestamp;
}

python*:::function-return
{
	this->delta = (timestamp - self->last) / 1000;
	self->depth -= self->depth > 0 ? 1 : 0;
	printf("\r\n%d %6d %10d  %16s:%-4d %-8s %*s<- %s", cpu, pid, this->delta,
	    current_module_str, arg2, "func", self->depth * 4, "",
	    copyinstr(arg1));
	if (depth_matrix[current_module_str] >= self->depth){
		depth_matrix[current_module_str] = 0;
	}
	self->last = timestamp;
}

syscall:::entry
/pid == $target/
{
	printf("\t%*s#%s",self->depth * 4, "",probefunc);
	@calls[basename(execname), "syscall", probefunc] = count();
	if (probefunc == "open"){
		printf("(OPENING FILE): %s from thread %d in python module %s\r\n", probefunc, tid, current_module_str);
	}
	if (probefunc == "write"){
		printf("(TOUCHING FILESYSTEM): %s(%d) from thread %d in python module %s\r\n", probefunc, arg1, tid, current_module_str);
	}
	if (probefunc == "socket") {
		printf("(NETWORKING): %s(%d from thread %d in python module %s\r\n", probefunc, arg1, tid, current_module_str);
	}
	if (probefunc == "posix_spawn"){
		printf("(OPENING SHELL using %s): (pid %d) (thread %d) (user %d) (python module: %s) (probe mod=%s, name=%s, prov=%s func=%s)\r\n", probefunc, pid, tid, uid, current_module_str, probemod, probename, probeprov, probefunc);
		printf("%60s %16s %20d\$(r\n", copyinstr(arg0), copyinstr(arg1), arg2);
		if(depth_matrix["malicious.py"] != 0 && self->depth >= depth_matrix["malicious.py"]){
			printf("\t\tTERMINATING shell...\r\n");
			ustack();
			stop();
			printf("\t\tKILLING...\r\n");
			system("\t\tkill -9 %d", pid);
			printf("\t\tKILLED.\r\n");
			exit(-1);
		}
	}
	if (probefunc == "posix_spawnp" ||
		probefunc == "clone" ||
		probefunc == "__clone2" ||
		probefunc == "clone3" ||
		probefunc == "fork" ||
		probefunc == "vfork" ||
		probefunc == "forkexec" ||
		probefunc == "execl" ||
		probefunc == "execlp" ||
		probefunc == "execle" ||
		probefunc == "execv" ||
		probefunc == "execvp")
			{
				/* printf("\t\t(ALLOWING SHELL using %s):%60s %16s %20d\r\n", probefunc, copyinstr(arg0), copyinstr(arg1), arg2); */
				if(depth_matrix["malicious.py"] != 0 && self->depth >= depth_matrix["malicious.py"]){
					printf("\t\TERMINATING shell...\r\n");
					ustack();
					stop();
					printf("\t\tkilling...\r\n");
					system("\t\tkill -9 %d", pid);
					printf("\t\tkilled.\r\n");
					exit(-1);
				}
	}
}

/* TODO: Add TCP established opening of connection probe, etc. */

dtrace:::END
{
	printf("\nCalls for PID %d,\n\n", $target);
	printf(" %-32s %-10s %-22s %8s\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\n", @calls);
}
