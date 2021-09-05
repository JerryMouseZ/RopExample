#include <sys/ptrace.h>
#include <sys/reg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>  
#include <sys/wait.h>

pid_t child_process(char * path, char ** argv)
{
    pid_t pid = fork();
    if(pid != 0)
        return pid;
    
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execv(path, argv);
    exit(0);
    return pid;
}

int main(){
    pid_t  child;
    int status;
    char * argv_list[] = {"ls", "-lart", "/home", NULL};
    child = child_process("/bin/ls", argv_list);
    waitpid(child, &status, 0);
    long orig_eax = ptrace(PTRACE_PEEKUSER,
                      child, 8 * ORIG_RAX,
                      NULL);
    printf("The child made a "
           "system call %ld\n", orig_eax);
    ptrace(PTRACE_CONT, child, NULL, NULL);

    exit(0);
    return 0;
}
