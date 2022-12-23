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
	/* requests START */
/* strlen(dirname(_current_module_str)) >= strlen(dirname("requests")) && */
/* strstr(dirname(_current_module_str), dirname("requests")) != 0 */
if ((depth_matrix["requests"] != 0) && (self->depth >= depth_matrix["requests"])){
	    if (latest_supervised_module == ""){
			latest_supervised_module = "requests"
		}
		else{
			if (depth_matrix["requests"] > depth_matrix[latest_supervised_module]){
				latest_supervised_module = "requests"
			}	
		}
		
/* printf("GOT %s %s %d", _current_module_str,  dirname("requests"), strstr(_current_module_str,  dirname("requests")) */
		if (depth_matrix["requests"] == depth_matrix[latest_supervised_module])
		{
			if (probefunc != "fchmod" && probefunc != "getentropy" && probefunc != "getpgrp" && probefunc != "getrlimit" && probefunc != "shm_open" && probefunc != "sysctlbyname" && probefunc != "access" && probefunc != "munmap" && probefunc != "issetugid" && probefunc != "readlink" && probefunc != "write" && probefunc != "fcntl" && probefunc != "fstatfs64" && probefunc != "getdirentries64" && probefunc != "mprotect" && probefunc != "fcntl_nocancel" && probefunc != "madvise" && probefunc != "mmap" && probefunc != "read_nocancel" && probefunc != "select" && probefunc != "sigprocmask" && probefunc != "close_nocancel" && probefunc != "write_nocancel" && probefunc != "open_nocancel" && probefunc != "close" && probefunc != "open" && probefunc != "sigaction" && probefunc != "lseek" && probefunc != "fstat64" && probefunc != "read" && probefunc != "ioctl" && probefunc != "stat64"){
				printf("\n*SUPERVISED FLOW: syscall '%s' called in '%s' from '%s'; which entered at depth %d;\nThe supervised module is %s which entered the stack in depth %d;\r\n", probefunc, _current_module_str, "requests", depth_matrix["requests"],  latest_supervised_module, depth_matrix[latest_supervised_module]);
				    if(depth_matrix["requests"]!= 0 && self->depth >= depth_matrix["requests"] && depth_matrix["requests"] >= depth_matrix[latest_supervised_module])
				{                ustack();
                printf("\t####################\r\n");
                printf("\t\tKilling process; depth=%d sandboxed_depth=%d module=%s\r\n", self->depth, depth_matrix[_current_module_str], _current_module_str);
                printf("\t\tIf this behavior is unexpected, add the syscall '%s' to your list. The policy that blocked this syscall is logged above the stackstrace.\r\n", probefunc);
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                printf("\t####################\r\n");
                exit(-1);}

			}
		}
}
/* requests END */

/* fastapi START */
/* strlen(dirname(_current_module_str)) >= strlen(dirname("fastapi")) && */
/* strstr(dirname(_current_module_str), dirname("fastapi")) != 0 */
if ((depth_matrix["fastapi"] != 0) && (self->depth >= depth_matrix["fastapi"])){
	    if (latest_supervised_module == ""){
			latest_supervised_module = "fastapi"
		}
		else{
			if (depth_matrix["fastapi"] > depth_matrix[latest_supervised_module]){
				latest_supervised_module = "fastapi"
			}	
		}
		
/* printf("GOT %s %s %d", _current_module_str,  dirname("fastapi"), strstr(_current_module_str,  dirname("fastapi")) */
		if (depth_matrix["fastapi"] == depth_matrix[latest_supervised_module])
		{
			if (probefunc != "bind" && probefunc != "fchmod" && probefunc != "getentropy" && probefunc != "getpgrp" && probefunc != "getrlimit" && probefunc != "shm_open" && probefunc != "sysctlbyname" && probefunc != "access" && probefunc != "munmap" && probefunc != "issetugid" && probefunc != "readlink" && probefunc != "write" && probefunc != "fcntl" && probefunc != "fstatfs64" && probefunc != "getdirentries64" && probefunc != "mprotect" && probefunc != "fcntl_nocancel" && probefunc != "madvise" && probefunc != "mmap" && probefunc != "read_nocancel" && probefunc != "select" && probefunc != "sigprocmask" && probefunc != "close_nocancel" && probefunc != "write_nocancel" && probefunc != "open_nocancel" && probefunc != "close" && probefunc != "open" && probefunc != "sigaction" && probefunc != "lseek" && probefunc != "fstat64" && probefunc != "read" && probefunc != "ioctl" && probefunc != "stat64" && probefunc != "read" && probefunc != "pipe" && probefunc != "listen" && probefunc != "poll" && probefunc != "sigreturn" && probefunc != "getsockname" && probefunc != "kqueue" && probefunc != "kevent" && probefunc != "getpeername" && probefunc != "getpgrp" && probefunc != "listen" && probefunc != "pipe" && probefunc != "poll" && probefunc != "setsockopt" && probefunc != "shm_open" && probefunc != "socket" && probefunc != "socketpair" && probefunc != "sysctlbyname" && probefunc != "accept" && probefunc != "access" && probefunc != "getrlimit" && probefunc != "kqueue" && probefunc != "readlink" && probefunc != "recvfrom" && probefunc != "getsockname" && probefunc != "issetugid" && probefunc != "sendto" && probefunc != "write" && probefunc != "read_nocancel" && probefunc != "getentropy" && probefunc != "sigprocmask" && probefunc != "fstatfs64" && probefunc != "getdirentries64" && probefunc != "munmap" && probefunc != "madvise" && probefunc != "select" && probefunc != "write_nocancel" && probefunc != "sigaction" && probefunc != "fcntl_nocancel" && probefunc != "fcntl" && probefunc != "close_nocancel" && probefunc != "open_nocancel" && probefunc != "mprotect" && probefunc != "mmap" && probefunc != "kevent" && probefunc != "open" && probefunc != "close" && probefunc != "lseek" && probefunc != "ioctl" && probefunc != "read" && probefunc != "fstat64" && probefunc != "stat64"){
				printf("\n*SUPERVISED FLOW: syscall '%s' called in '%s' from '%s'; which entered at depth %d;\nThe supervised module is %s which entered the stack in depth %d;\r\n", probefunc, _current_module_str, "fastapi", depth_matrix["fastapi"],  latest_supervised_module, depth_matrix[latest_supervised_module]);
				    if(depth_matrix["fastapi"]!= 0 && self->depth >= depth_matrix["fastapi"] && depth_matrix["fastapi"] >= depth_matrix[latest_supervised_module])
				{                ustack();
                printf("\t####################\r\n");
                printf("\t\tKilling process; depth=%d sandboxed_depth=%d module=%s\r\n", self->depth, depth_matrix[_current_module_str], _current_module_str);
                printf("\t\tIf this behavior is unexpected, add the syscall '%s' to your list. The policy that blocked this syscall is logged above the stackstrace.\r\n", probefunc);
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                printf("\t####################\r\n");
                exit(-1);}

			}
		}
}
/* fastapi END */

/* uvicorn START */
/* strlen(dirname(_current_module_str)) >= strlen(dirname("uvicorn")) && */
/* strstr(dirname(_current_module_str), dirname("uvicorn")) != 0 */
if ((depth_matrix["uvicorn"] != 0) && (self->depth >= depth_matrix["uvicorn"])){
	    if (latest_supervised_module == ""){
			latest_supervised_module = "uvicorn"
		}
		else{
			if (depth_matrix["uvicorn"] > depth_matrix[latest_supervised_module]){
				latest_supervised_module = "uvicorn"
			}	
		}
		
/* printf("GOT %s %s %d", _current_module_str,  dirname("uvicorn"), strstr(_current_module_str,  dirname("uvicorn")) */
		if (depth_matrix["uvicorn"] == depth_matrix[latest_supervised_module])
		{
			if (probefunc != "getpeername" && probefunc != "getpgrp" && probefunc != "listen" && probefunc != "pipe" && probefunc != "poll" && probefunc != "setsockopt" && probefunc != "shm_open" && probefunc != "socket" && probefunc != "socketpair" && probefunc != "sysctlbyname" && probefunc != "accept" && probefunc != "access" && probefunc != "getrlimit" && probefunc != "kqueue" && probefunc != "readlink" && probefunc != "recvfrom" && probefunc != "getsockname" && probefunc != "issetugid" && probefunc != "sendto" && probefunc != "write" && probefunc != "read_nocancel" && probefunc != "getentropy" && probefunc != "sigprocmask" && probefunc != "fstatfs64" && probefunc != "getdirentries64" && probefunc != "munmap" && probefunc != "madvise" && probefunc != "select" && probefunc != "write_nocancel" && probefunc != "sigaction" && probefunc != "fcntl_nocancel" && probefunc != "fcntl" && probefunc != "close_nocancel" && probefunc != "open_nocancel" && probefunc != "mprotect" && probefunc != "mmap" && probefunc != "kevent" && probefunc != "open" && probefunc != "close" && probefunc != "lseek" && probefunc != "ioctl" && probefunc != "read" && probefunc != "fstat64" && probefunc != "stat64"){
				printf("\n*SUPERVISED FLOW: syscall '%s' called in '%s' from '%s'; which entered at depth %d;\nThe supervised module is %s which entered the stack in depth %d;\r\n", probefunc, _current_module_str, "uvicorn", depth_matrix["uvicorn"],  latest_supervised_module, depth_matrix[latest_supervised_module]);
				    if(depth_matrix["uvicorn"]!= 0 && self->depth >= depth_matrix["uvicorn"] && depth_matrix["uvicorn"] >= depth_matrix[latest_supervised_module])
				{                ustack();
                printf("\t####################\r\n");
                printf("\t\tKilling process; depth=%d sandboxed_depth=%d module=%s\r\n", self->depth, depth_matrix[_current_module_str], _current_module_str);
                printf("\t\tIf this behavior is unexpected, add the syscall '%s' to your list. The policy that blocked this syscall is logged above the stackstrace.\r\n", probefunc);
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                printf("\t####################\r\n");
                exit(-1);}

			}
		}
}
/* uvicorn END */
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
