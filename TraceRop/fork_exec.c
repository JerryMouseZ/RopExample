#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>  
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "mem.h"

#define DEBUG

#ifdef DEBUG
#define debug_printf(...) \
    do { \
        fprintf(stderr, "\nIn %s - function %s at line %d: ", __FILE__, __func__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)


#define debug_condition_printf(condition, ...) \
    do { \
        if(condition) { \
            fprintf(stderr, "\nIn %s - function %s at line %d: ", __FILE__, __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while(0)

#else
#define debug_printf(...) (void) 0
#define debug_condition_printf(...) (void) 0
#endif

int pipefd[2];
pid_t start_child(const char* program, char **argv){
    //we need a readline function
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
    } else if (pid == 0) {
        close(pipefd[0]);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // This code runs in the child process.
        int output_fd = pipefd[1];
        fcntl(output_fd, F_SETFL, O_NONBLOCK);
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

long get_instr_addr(int fd)
{
    FILE* in = fdopen(fd, "r");
    char *line = NULL;
    int nread = 0;
    int len = 0;
    while((nread = getline(&line, &len, in)) != -1)
    {
        if(strstr(line, "&= 0x11") != NULL){
            for(int i = 0; i < 3; ++i)
            {
                getline(&line, &len, in);
            }
            long addr = strtol(line, NULL, 16);
            if(addr != 0){
                debug_printf("[get addr] %lx\n", addr);
                free(line);
                return addr - 3;
            }
        }
    }
    free(line);
    return 0;
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
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    waitpid(child, &status, 0);

    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);

    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    waitpid(child, &status, 0);
    sleep(1);
    long instr_addr = get_instr_addr(pipefd[0]);
    char ins_buffer[1024] = {0};
    int ret = readmemory(child, ins_buffer, (char *) instr_addr, 256);
    debug_condition_printf(ret <= 0, "read memory error at %lx\n", instr_addr);

    disas_raw_code(ins_buffer, 256, instr_addr);
    

    ptrace(PTRACE_DETACH, child, 0, 0);
    close(pipefd[0]);

    exit(0);
    return 0;
}
