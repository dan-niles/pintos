#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"
void syscall_init(void);

struct child_process
{
    int pid;
    int wait;
    int exit;
    int load_status;
    int status;
    struct semaphore exit_sema;
    struct semaphore load_sema;
    struct list_elem elem;
};

struct current_file
{
    struct file *file;
    int fd;
    struct list_elem elem;
};

void syscall_halt(void);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned size);
int syscall_write(int fd, const void *buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);

int fetch_page_ptr(const void *vaddr);
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