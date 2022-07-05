                ustack();
                stop();
                printf("\t\tKILLING...\r\n");
                system("\t\tkill -9 %d", pid);
                printf("\t\tKILLED.\r\n");
                exit(-1);