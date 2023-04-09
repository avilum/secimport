#!/usr/sbin/dtrace -Zs

#pragma D option destructive
#pragma D option quiet
#pragma D option switchrate=1
#pragma D option cleanrate=50hz
/*
    "dirty" variable drops per <my use case>
    default -> ~20k
    10 Hz -> ~15k
    20 Hz -> ~10k
    30 Hz -> ~2k
    40 Hz -> ~1k
    50 Hz (max) -> < 200
*/

#pragma D option dynvarsize=400000
/*
     10,000 @ 50 Hz -> ~25k+
    100,000 @ 50 Hz -> ~20k
    200,000 @ 50 Hz -> ~3k
    300,000 @ 50 Hz -> ~1k
    400,000 @ 50 Hz -> 0
    400,000 @ 25 Hz -> ~2k
    500,000 @ 25 Hz -> ~1k
*/

/* A depth matrix for modules by name, maps each module (string) to the stack depth (int) at which it entered. */
int depth_matrix[string];
self int depth;
string current_module_str;
string previous_module_str;
string latest_supervised_module;

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

	/* if (strstr(_current_module_str, "###MODULE_NAME###") != 0){
		printf("---! in module %s \r\n", "###MODULE_NAME###");
	} */

	/* Saving the stack depth for each module, assuming interpreter with GIL will run line-by-line. */
	if (depth_matrix[current_module_str] > self->depth){
		depth_matrix[current_module_str] = 0;
	}
	if (depth_matrix[current_module_str] == 0){
		/* printf("---> (%d) %s\r\n", self->depth,  _current_module_str); */
		depth_matrix[current_module_str] = self->depth;
	}
	/* depth_matrix[current_module_str] = self->depth; */
}

python*:::function-return
{
	this->delta = (timestamp - self->last) / 1000;
	self->depth -= self->depth > 0 ? 1 : 0;
	/* printf("<--- (%d) %s\r\n", self->depth, _current_module_str); */
	if (depth_matrix[current_module_str] > self->depth){
		depth_matrix[current_module_str] = 0;
	}
}

syscall:::entry
/pid == $target/
{
	@calls[basename(execname), "syscall", probefunc] = count();
	/* printf("\n@%s", probefunc); */
	###SUPERVISED_MODULES_PROBES###
}

/*
syscall:::return
/pid == $target/
{
	printf("\n");
} */


dtrace:::END
{
	printf("System Calls (%d)\r\n\r\n", $target);
	printf(" %-32s %-10s %-22s %8s\r\n", "FILE", "TYPE", "NAME", "COUNT");
	printa(" %-32s %-10s %-22s %@8d\r\n", @calls);
	/* print(depth_matrix); */
}
