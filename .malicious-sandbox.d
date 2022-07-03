#!/usr/sbin/dtrace -Zs

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1

/* A depth matrix for modules by name, maps each module (string) to the stack depth (int) at which it entered. */
int depth_matrix[string];
self int depth;
string current_module_str;
string previous_module_str;

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
	_current_module_str = stringof(basename(copyinstr(arg0)));
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
	printf("\t\t\t DEPTH=%d\r\n", self->depth);
	if (depth_matrix[current_module_str] >= self->depth){
		depth_matrix[current_module_str] = 0;
	}
			printf("\r\n%d %6d %10d  %16s:%-4d %-8s %*s<- %s", cpu, pid, this->delta, 
				current_module_str, arg2, "func", self->depth * 4, "",
				copyinstr(arg1));
	self->last = timestamp;
}

syscall:::entry
/pid == $target/
{	
	@calls[basename(execname), "syscall", probefunc] = count();
	        printf("\t\t#%s,\r\n", probefunc);;
    if (probefunc == "open" || probefunc == "write")
{        printf("(TOUCHING FILESYSTEM): %s(%d) from thread %d in python module %s\r\n", probefunc, arg1, tid, current_module_str);}
    if (probefunc == "socket"){
        printf("\t\t(NETWORKING): %s(%d from thread %d in python module %s\r\n", probefunc, arg1, tid, current_module_str);}
    if (probefunc == "posix_spawn" ||
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
        probefunc == "execvp"){
        printf("\t\t\t\tDETECTED SHELL, depth=%d sandboxed_depth=%d\r\n", self->depth, depth_matrix["malicious.py"]);
        if(depth_matrix["malicious.py"] != 0 && self->depth >= depth_matrix["malicious.py"]){
            printf("\t\tTERMINATING shell...\r\n");
            ustack();
            stop();
            printf("\t\tKILLING...\r\n");
            system("\t\tkill -9 %d", pid);
            printf("\t\tKILLED.\r\n");
            exit(-1);
        }}

}

dtrace:::END
{
	printf("System Calls (%d):,\r\n\r\n", $target);
	printf(" %-32s %-10s %-22s %8s\r\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\r\n", @calls);
}
