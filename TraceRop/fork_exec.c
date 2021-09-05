#include <sys/ptrace.h>
#include <sys/reg.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>  
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

int pipefd[2];
pid_t start_child(const char* program, char **argv)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
    } else if (pid == 0) {
        close(pipefd[0]);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // This code runs in the child process.
        int output_fd = pipefd[1];
        // Replace the child's stdout and stderr handles with the log file handle:
        if (dup2(output_fd, STDOUT_FILENO) < 0) {
            perror("dup2 (stdout)");
            exit(1);
        }
        if (dup2(output_fd, STDERR_FILENO) < 0) {
            perror("dup2 (stderr)");
            exit(1);
        }
        if (execvp(program, argv) < 0) {
            perror("execl");
            exit(1);
        }
    }
    return pid;
}

int main(){
    if(pipe(pipefd) == -1){
        perror("pipe");
        exit(-1);
    }
    int status;
    char * argv_list[] = {"ch", "-dump:encoder", "-DebugBreak:1", "template.js", NULL};
    pid_t  child;
    child = start_child("ch", argv_list);
    if(child == -1){
        perror("fork");
        exit(-1);
    }

    close(pipefd[1]);
    waitpid(child, &status, 0);
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);
    ptrace(PTRACE_SINGLESTEP, child, 0, 0);

    while(1)
    {
        waitpid(child, &status, 0);
        if(WIFEXITED(status))
            break;
        char ch;
        // blocking here
        while(read(pipefd[0], &ch, 1) > 0)
        {
            printf("%c", ch);
        }
        printf("\n");
        ptrace(PTRACE_DETACH, child, 0, 0);
    }
    close(pipefd[0]);

    exit(0);
    return 0;
}
