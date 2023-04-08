        printf("\t\t\t\tDETECTED SHELL, depth=%d sandboxed_depth=%d sandboxed_module=%s current_module=%s\r\n", self->depth, depth_matrix["###MODULE_NAME###"], "###MODULE_NAME###", _current_module_str);
        printf("\t\tTERMINATING shell...\r\n");
        ustack();
        stop();
        printf("\t\tKILLING...\r\n");
        system("\t\tkill -9 %d", pid);
        printf("\t\tKILLED.\r\n");
        exit(-1);
