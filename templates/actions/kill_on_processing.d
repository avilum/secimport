        printf("\t\t\t\tDETECTED SHELL, depth=%d sandboxed_depth=%d\r\n", self->depth, depth_matrix["###MODULE_NAME###"]);
        if((self->depth == 0 && depth_matrix["###MODULE_NAME###"] == 0) ||
            (depth_matrix["###MODULE_NAME###"] != 0 && self->depth >= depth_matrix["###MODULE_NAME###"])){
                printf("\t\tTERMINATING shell...\r\n");
                ustack();
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                exit(-1);
        }