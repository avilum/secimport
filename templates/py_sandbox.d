#!/usr/sbin/dtrace -Zs

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1

self int depth;
string current_module_str;
self int sandbox_module_reached;

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
	_current_module_str = stringof(basename(copyinstr(arg0)));
	/* ustack(); */
	if(_current_module_str == "malicious.py"){ 
		sandbox_module_reached = 1;
	}
	current_module_str =  _current_module_str;
	this->delta = (timestamp - self->last) / 1000;
	printf("%d %6d %10d  %16s:%-4d %-8s %*s-> %s\n", cpu, pid, this->delta, 
	    current_module_str, arg2, "func", self->depth * 2, "",
	    copyinstr(arg1));
	self->depth++;
	self->last = timestamp;
}

python*:::function-return
{	
	/* ustack(); */
	this->delta = (timestamp - self->last) / 1000;
	self->depth -= self->depth > 0 ? 1 : 0;
	printf("\r\n%d %6d %10d  %16s:%-4d %-8s %*s<- %s\r\n", cpu, pid, this->delta, 
	    current_module_str, arg2, "func", self->depth * 4, "",
	    copyinstr(arg1));
	self->last = timestamp;
}

syscall:::entry
/pid == $target/
{	
	/*
	Examples based on: 
		https://docs.oracle.com/cd/E18752_01/html/819-5488/gcfpz.html
		https://opensource.apple.com/source/dtrace/dtrace-147/DTTk/dtruss.auto.html
		https://www.brendangregg.com/Articles/FreeBSDwiki_DTrace_Tutorial_2014.pdf
			
			probefunc == "posix_spawnp" ||
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
			probefunc == "execvp"

	 */
	if (probefunc == "posix_spawn")
			{
				printf("\t\t\r\n(OPENING SHELL using %s): (pid %d) (thread %d) (user %d) (python module: %s) (probe mod=%s, name=%s, prov=%s func=%s)\r\n", probefunc, pid, tid, uid, current_module_str, probemod, probename, probeprov, probefunc);
				printf("\t\t%60s %16s %20d\r\n", copyinstr(arg0), copyinstr(arg1), arg2);
				if (sandbox_module_reached){
					printf("\t\tSTOPPING shell...\r\n");
					trace(pid);
					ustack();
					stop();
					printf("\t\tKILLING...\r\n");
					system("\t\tkill -9 %d", pid);
					printf("\t\tKILLED.\r\n");
					exit(-1);
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
				printf("\t\t(OPENING SHELL using %s):%60s %16s %20d\r\n", probefunc, copyinstr(arg0), copyinstr(arg1), arg2);
		}
		else {
			printf("\t\tAllowing shell for %s", current_module_str);
		}
	}
	if (probefunc == "open"){
		printf("\t\t(OPENING FILE): %s from thread %d in python module %s\r\n", probefunc, tid, current_module_str);
	}
	if (probefunc == "write"){
		printf("\t\t(TOUCHING FILESYSTEM): %s(%d) from thread %d in python module %s\r\n", probefunc, arg1, tid, current_module_str);
	}
	else{
		printf("\t\t(SYSCALL) %s,\r\n", probefunc);
	}
	@calls[basename(execname), "syscall", probefunc] = count();
}

/* TODO: Add TCP established opening of connection probe, etc. */

dtrace:::END
{
	printf("\nCalls for PID %d,\n\n", $target);
	printf(" %-32s %-10s %-22s %8s\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\n", @calls);
}
