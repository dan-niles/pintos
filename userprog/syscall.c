#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 5

static void syscall_handler(struct intr_frame *);
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

struct lock file_system_lock;
bool FILE_LOCK_INIT = false;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  printf("system call!\n");

  if (!FILE_LOCK_INIT)
  {
    lock_init(&file_system_lock);
    FILE_LOCK_INIT = true;
  }

  int arg[MAX_ARGS];
  int esp = getpage_ptr((const void *)f->esp);

  switch (*(int *)esp)
  {
  case SYS_HALT:
    syscall_halt();
    break;

  case SYS_EXIT:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);
    syscall_exit(arg[0]);
    break;

  case SYS_EXEC:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);

    // check if command line is valid
    validate_str((const void *)arg[0]);

    // get page pointer
    arg[0] = getpage_ptr((const void *)arg[0]);
    /* syscall_exec(const char* cmd_line) */
    f->eax = syscall_exec((const char *)arg[0]); // execute the command line
    break;

  case SYS_WAIT:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);
    f->eax = syscall_wait(arg[0]);
    break;

  case SYS_CREATE:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 2);

    // check if command line is valid
    validate_str((const void *)arg[0]);

    // get page pointer
    arg[0] = getpage_ptr((const void *)arg[0]);

    /* syscall_create(const char* file, unsigned initial_size) */
    f->eax = syscall_create((const char *)arg[0], (unsigned)arg[1]); // create this file
    break;

  case SYS_REMOVE:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);

    /* check if command line is valid */
    validate_str((const void *)arg[0]);

    // get page pointer
    arg[0] = getpage_ptr((const void *)arg[0]);

    /* syscall_remove(const char* file) */
    f->eax = syscall_remove((const char *)arg[0]); // remove this file
    break;

  case SYS_OPEN:
    // fill arg with amount of arguments needed
    get_args(f, &arg[0], 1);

    /* Check if command line is valid.
     * We do not want to open junk which can cause a crash
     */
    validate_str((const void *)arg[0]);

    // get page pointer
    arg[0] = getpage_ptr((const void *)arg[0]);

    /* syscall_open(int fd) */
    f->eax = syscall_open((const char *)arg[0]); // open this file
    break;

  case SYS_FILESIZE:
    // fill arg with amount of arguments needed
    get_args(f, &arg[0], 1);

    /* syscall_filesize (const char *file) */
    f->eax = syscall_filesize(arg[0]); // obtain file size
    break;

  case SYS_READ:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 3);

    /* Check if the buffer is valid.
     * We do not want to mess with a buffer that is out of our
     * reserved virtual memory
     */
    validate_buffer((const void *)arg[1], (unsigned)arg[2]);

    // get page pointer
    arg[1] = getpage_ptr((const void *)arg[1]);

    /* syscall_write (int fd, const void * buffer, unsigned bytes)*/
    f->eax = syscall_read(arg[0], (void *)arg[1], (unsigned)arg[2]);
    break;

  case SYS_WRITE:

    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 3);

    /* Check if the buffer is valid.
     * We do not want to mess with a buffer that is out of our
     * reserved virtual memory
     */
    validate_buffer((const void *)arg[1], (unsigned)arg[2]);

    // get page pointer
    arg[1] = getpage_ptr((const void *)arg[1]);

    /* syscall_write (int fd, const void * buffer, unsigned bytes)*/
    f->eax = syscall_write(arg[0], (const void *)arg[1], (unsigned)arg[2]);
    break;

  case SYS_SEEK:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 2);
    /* syscall_seek(int fd, unsigned position) */
    syscall_seek(arg[0], (unsigned)arg[1]);
    break;

  case SYS_TELL:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);
    /* syscall_tell(int fd) */
    f->eax = syscall_tell(arg[0]);
    break;

  case SYS_CLOSE:
    // fill arg with the amount of arguments needed
    get_args(f, &arg[0], 1);
    /* syscall_close(int fd) */
    syscall_close(arg[0]);
    break;

  default:
    break;
  }

  thread_exit();
}

/* Terminates Pintos by calling shutdown_power_off() */
void syscall_halt(void)
{
  shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. */
void syscall_exit(int status)
{
  struct thread *cur = thread_current();
  if (is_thread_alive(cur->parent) && cur->cp)
  {
    if (status < 0)
    {
      status = -1;
    }
    cur->cp->status = status;
  }
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid).  */
pid_t syscall_exec(const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process *child_process_ptr = find_child_process(pid);
  if (!child_process_ptr)
  {
    return -1;
  }
  /* check if process if loaded */
  if (child_process_ptr->load_status == 0)
  {
    sema_down(&child_process_ptr->load_sema);
  }
  /* check if process failed to load */
  if (child_process_ptr->load_status == 2)
  {
    remove_child_process(child_process_ptr);
    return -1;
  }
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
int syscall_wait(pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. */
bool syscall_create(const char *file, unsigned initial_size)
{
  lock_acquire(&file_system_lock);
  bool successful = filesys_create(file, initial_size);
  lock_release(&file_system_lock);
  return successful;
}

/* Deletes the file called file. Returns true if successful, false otherwise. */
bool syscall_remove(const char *file)
{
  lock_acquire(&file_system_lock);
  bool successful = filesys_remove(file); // from filesys.h
  lock_release(&file_system_lock);
  return successful;
}

/* Opens the file called file.
   Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened. */
int syscall_open(const char *file)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = filesys_open(file); // from filesys.h
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return -1;
  }
  int fd = add_file(file_ptr);
  lock_release(&file_system_lock);
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
int syscall_filesize(int fd)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return -1;
  }
  int filesize = file_length(file_ptr); // from file.h
  lock_release(&file_system_lock);
  return filesize;
}

#define STD_INPUT 0
#define STD_OUTPUT 1

/* Reads size bytes from the file open as fd into buffer. */
int syscall_read(int fd, void *buffer, unsigned size)
{
  if (size <= 0)
  {
    return size;
  }

  if (fd == STD_INPUT)
  {
    unsigned i = 0;
    uint8_t *local_buf = (uint8_t *)buffer;
    for (; i < size; i++)
    {
      // retrieve pressed key from the input buffer
      local_buf[i] = input_getc(); // from input.h
    }
    return size;
  }

  /* read from file */
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return -1;
  }
  int bytes_read = file_read(file_ptr, buffer, size); // from file.h
  lock_release(&file_system_lock);
  return bytes_read;
}

/* Writes size bytes from buffer to the open file fd. */
int syscall_write(int fd, const void *buffer, unsigned size)
{
  if (size <= 0)
  {
    return size;
  }
  if (fd == STD_OUTPUT)
  {
    putbuf(buffer, size); // from stdio.h
    return size;
  }

  // start writing to file
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return -1;
  }
  int bytes_written = file_write(file_ptr, buffer, size); // file.h
  lock_release(&file_system_lock);
  return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. */
void syscall_seek(int fd, unsigned position)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return;
  }
  file_seek(file_ptr, position);
  lock_release(&file_system_lock);
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned syscall_tell(int fd)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return -1;
  }
  off_t offset = file_tell(file_ptr); // from file.h
  lock_release(&file_system_lock);
  return offset;
}

/* Closes file descriptor fd. */
void syscall_close(int fd)
{
  lock_acquire(&file_system_lock);
  process_close_file(fd);
  lock_release(&file_system_lock);
}

/* function to check if string is valid */
void validate_str(const void *str)
{
  for (; *(char *)getpage_ptr(str) != 0; str = (char *)str + 1)
    ;
}

/* function to check if buffer is valid */
void validate_buffer(const void *buf, unsigned byte_size)
{
  unsigned i = 0;
  char *local_buffer = (char *)buf;
  for (; i < byte_size; i++)
  {
    validate_ptr((const void *)local_buffer);
    local_buffer++;
  }
}

/* get the pointer to page */
int getpage_ptr(const void *vaddr)
{
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    syscall_exit(-1);
  }
  return (int)ptr;
}

/* find a child process based on pid */
struct child_process *find_child_process(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;

  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    if (pid == cp->pid)
    {
      return cp;
    }
  }
  return NULL;
}

/* remove a specific child process */
void remove_child_process(struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);
}

/* remove all child processes for a thread */
void remove_all_child_processes(void)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->child_list);

  for (; e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    list_remove(&cp->elem); // remove child process
    free(cp);
  }
}

/* add file to file list and return file descriptor of added file*/
int add_file(struct file *file_name)
{
  struct process_file *process_file_ptr = malloc(sizeof(struct process_file));
  if (!process_file_ptr)
  {
    return -1;
  }
  process_file_ptr->file = file_name;
  process_file_ptr->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &process_file_ptr->elem);
  return process_file_ptr->fd;
}

/* get arguments from stack */
void get_args(struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
  {
    ptr = (int *)f->esp + i + 1;
    validate_ptr((const void *)ptr);
    args[i] = *ptr;
  }
}

/* get file that matches file descriptor */
struct file *
get_file(int filedes)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);

  for (; e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry(e, struct process_file, elem);
    if (filedes == process_file_ptr->fd)
    {
      return process_file_ptr->file;
    }
  }
  return NULL; // nothing found
}

/* close the desired file descriptor */
void process_close_file(int file_descriptor)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);

  for (; e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry(e, struct process_file, elem);
    if (file_descriptor == process_file_ptr->fd || file_descriptor == -1)
    {
      file_close(process_file_ptr->file);
      list_remove(&process_file_ptr->elem);
      free(process_file_ptr);
      if (file_descriptor != -1)
      {
        return;
      }
    }
  }
}