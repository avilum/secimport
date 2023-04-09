		printf("\r\n%d %6d %10d  %16s:%-4d %-8s %*s<- %s  (stack depth=%d)", cpu, pid, this->delta,
				current_module_str, arg2, "func", self->depth * 4, "",
				copyinstr(arg1), self->depth);
