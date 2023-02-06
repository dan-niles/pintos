#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

#define STD_INPUT 0
#define STD_OUTPUT 1

void syscall_init(void);

int getpage_ptr(const void *vaddr);
struct child_process *find_child_process(int pid);
void remove_child_process(struct child_process *cp);
void remove_all_child_processes(void);
struct file *get_file(int fd);
void process_close_file(int fd);

int add_file(struct file *file);
void get_args(struct intr_frame *f, int *arg, int num_of_args);

void syscall_halt(void);
void syscall_exit(int status);
pid_t syscall_exec(const char *cmd_line);
int syscall_wait(pid_t pid);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned size);
int syscall_write(int fd, const void *buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fildes);
void syscall_close(int fd);

void validate_ptr(const void *vaddr);
void validate_str(const void *str);
void validate_buffer(const void *buf, unsigned size);

struct child_process
{
    int pid;
    int load_status;
    int wait;
    int exit;
    int status;
    struct semaphore load_sema;
    struct semaphore exit_sema;
    struct list_elem elem;
};

struct process_file
{
    struct file *file;
    int fd;
    struct list_elem elem;
};

bool FILE_LOCK_INIT = false;
struct lock file_system_lock;

#endif /* userprog/syscall.h */
