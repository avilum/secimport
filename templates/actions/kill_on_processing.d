        printf("\t\t\t\tDETECTED SHELL, depth=%d sandboxed_depth=%d\r\n", self->depth, depth_matrix["###MODULE_NAME###"]);
        
        /*
        If both module counter and depth are 0, or
        the module counter is higher than the depth, or
         */
        if((self->depth == 0 && depth_matrix["###MODULE_NAME###"] == 0) ||
            (depth_matrix["###MODULE_NAME###"] != 0 && self->depth > depth_matrix["###MODULE_NAME###"])){
                printf("\t\tTERMINATING shell...\r\n");
                ustack();
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                exit(-1);
        }