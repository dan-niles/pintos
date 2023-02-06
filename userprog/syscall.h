#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"
void syscall_init(void);

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

int getpage_ptr(const void *vaddr);
struct child_process *find_child_process(int pid);
void remove_child_process(struct child_process *cp);
void remove_all_child_processes(void);
struct file *get_file(int fd);
int add_file(struct file *file);

void process_close_file(int fd);
void syscall_exit(int status);

void validate_ptr(const void *vaddr);
void validate_str(const void *str);
void validate_buffer(const void *buf, unsigned size);

struct lock file_system_lock;
#endif /* userprog/syscall.h */