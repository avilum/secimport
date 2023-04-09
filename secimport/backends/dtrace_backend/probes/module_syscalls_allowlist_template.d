/* ###MODULE_NAME### START */
/* strlen(dirname(_current_module_str)) >= strlen(dirname("###MODULE_NAME###")) && */
/* strstr(dirname(_current_module_str), dirname("###MODULE_NAME###")) != 0 */
if ((depth_matrix["###MODULE_NAME###"] != 0) && (self->depth >= depth_matrix["###MODULE_NAME###"])){
	    if (latest_supervised_module == ""){
			latest_supervised_module = "###MODULE_NAME###"
		}
		else{
			if (depth_matrix["###MODULE_NAME###"] > depth_matrix[latest_supervised_module]){
				latest_supervised_module = "###MODULE_NAME###"
			}
		}

/* printf("GOT %s %s %d", _current_module_str,  dirname("###MODULE_NAME###"), strstr(_current_module_str,  dirname("###MODULE_NAME###")) */
		if (depth_matrix["###MODULE_NAME###"] == depth_matrix[latest_supervised_module])
		{
			if (###SYSCALL_FILTER###){
				printf("\n*SUPERVISED FLOW: syscall '%s' called in '%s' from '%s'; which entered at depth %d;\nThe supervised module is %s which entered the stack in depth %d;\r\n", probefunc, _current_module_str, "###MODULE_NAME###", depth_matrix["###MODULE_NAME###"],  latest_supervised_module, depth_matrix[latest_supervised_module]);
				###SUPERVISED_MODULES_FILTER###
				###SUPERVISED_MODULES_ACTION###
			}
		}
}
/* ###MODULE_NAME### END */
