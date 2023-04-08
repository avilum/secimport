#!/usr/sbin/dtrace -Zs

###DESTRUCTIVE###
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
	self->depth++;

	/* Memoizing the previous module and current module */
	_current_module_str = stringof(copyinstr(arg0));
	previous_module_str = stringof(current_module_str);
	current_module_str =  _current_module_str;

	/* Saving the stack depth for each module, assuming interpreter with GIL will run line-by-line. */
	if (depth_matrix[current_module_str] > self->depth){
		depth_matrix["###MODULE_NAME###"] = 0;
	}
	if (depth_matrix[current_module_str] == 0){
		depth_matrix[current_module_str] = self->depth;
	}

	###FUNCTION_ENTRY###
	self->last = timestamp;
}

python*:::function-return
{

	this->delta = (timestamp - self->last) / 1000;
	self->depth -= self->depth > 0 ? 1 : 0;
	if (depth_matrix["###MODULE_NAME###"] > self->depth){
		depth_matrix["###MODULE_NAME###"] = 0;
	}
	###FUNCTION_EXIT###
	self->last = timestamp;
}

syscall:::entry
/pid == $target/
{
	@calls[basename(execname), "syscall", probefunc] = count();
	###SYSCALL_ENTRY###
}

dtrace:::END
{
	printf("System Calls (%d):\r\n\r\n", $target);
	printf(" %-32s %-10s %-22s %8s\r\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\r\n", @calls);
}
