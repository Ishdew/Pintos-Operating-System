#include "userprog/syscall.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame *);

static void handle_invalid_access(void);
static struct file_desc *find_file_desc(int fd);
static bool put_user(uint8_t *udst, uint8_t byte);
static int get_user(const uint8_t *uaddr);
static int mem_read(void *src, void *dest, size_t bytes);
static void read_from_stack(struct intr_frame *f, void *dest, int ind);

void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *filename, unsigned initial_size);
bool sys_remove(const char *filename);
int sys_open(const char *filename);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

struct lock filesys_lock;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_handler(struct intr_frame *f)
{
  int syscall_number;
  read_from_stack(f, &syscall_number, 0);

  if (syscall_number == SYS_HALT)
  {
    sys_halt();
  }
  else if (syscall_number == SYS_EXIT)
  {
    int exit_code;
    read_from_stack(f, &exit_code, 1);
    sys_exit(exit_code);
    NOT_REACHED();
  }
  else if (syscall_number == SYS_EXEC)
  {
    void *cmd_line;
    read_from_stack(f, &cmd_line, 1);
    f->eax = (uint32_t)sys_exec((const char *)cmd_line);
  }
  else if (syscall_number == SYS_WAIT)
  {
    pid_t pid;
    read_from_stack(f, &pid, 1);
    f->eax = (uint32_t)sys_wait(pid);
  }
  else if (syscall_number == SYS_CREATE)
  {
    char *filename;
    unsigned initial_size;
    read_from_stack(f, &filename, 1);
    read_from_stack(f, &initial_size, 2);
    f->eax = (uint32_t)sys_create(filename, initial_size);
  }
  else if (syscall_number == SYS_REMOVE)
  {
    char *filename;
    read_from_stack(f, &filename, 1);
    f->eax = (uint32_t)sys_remove(filename);
  }
  else if (syscall_number == SYS_OPEN)
  {
    char *filename;
    read_from_stack(f, &filename, 1);
    f->eax = (uint32_t)sys_open(filename);
  }
  else if (syscall_number == SYS_FILESIZE)
  {
    int fd;
    read_from_stack(f, &fd, 1);
    f->eax = (uint32_t)sys_filesize(fd);
  }
  else if (syscall_number == SYS_READ)
  {
    int fd;
    void *buffer;
    unsigned size;
    read_from_stack(f, &fd, 1);
    read_from_stack(f, &buffer, 2);
    read_from_stack(f, &size, 3);
    f->eax = (uint32_t)sys_read(fd, buffer, size);
  }
  else if (syscall_number == SYS_WRITE)
  {
    int fd, return_code;
    void *buffer;
    unsigned int size;
    read_from_stack(f, &fd, 1);
    read_from_stack(f, &buffer, 2);
    read_from_stack(f, &size, 3);
    f->eax = (uint32_t)sys_write(fd, buffer, size);
  }
  else if (syscall_number == SYS_SEEK)
  {
    int fd;
    unsigned position;
    read_from_stack(f, &fd, 1);
    read_from_stack(f, &position, 2);
    sys_seek(fd, position);
  }
  else if (syscall_number == SYS_TELL)
  {
    int fd;
    read_from_stack(f, &fd, 1);
    f->eax = (uint32_t)sys_tell(fd);
  }
  else if (syscall_number == SYS_CLOSE)
  {
    int fd;
    read_from_stack(f, &fd, 1);
    sys_close(fd);
  }
  else
  {
    printf("[ERROR]: system call %d is unimplemented\n", syscall_number);
    sys_exit(-1);
  }
}

void sys_halt(void)
{
  shutdown_power_off();
  NOT_REACHED();
}

static void
handle_invalid_access(void)
{
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release(&filesys_lock);
  sys_exit(-1);
  NOT_REACHED();
}

void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  struct process_control_block *pcb = thread_current()->pcb;
  pcb->exited = true;
  pcb->exit_code = status;
  sema_up(&pcb->waiting_sema);
  thread_exit();
}

/* Runs command CMD_LINE.
   Returns tid of child thread if successful, -1 if a
   segfault occurs. */
pid_t sys_exec(const char *cmd_line)
{
  if (get_user((const uint8_t *)cmd_line) == -1)
    handle_invalid_access();

  /* Check validity of cmd_line string */
  for (int i = 0;; i++)
  {
    char temp = get_user((const uint8_t *)(cmd_line + i));
    if (temp == -1) /* Invalid memory */
    {
      handle_invalid_access();
    }
    else if (temp == 0) /* Null terminator */
      break;
  }

  lock_acquire(&filesys_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return pid;
}

int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

bool sys_create(const char *filename, unsigned initial_size)
{
  if (get_user(filename) == -1)
    handle_invalid_access();

  lock_acquire(&filesys_lock);
  bool return_value = filesys_create(filename, initial_size);
  lock_release(&filesys_lock);
  return return_value;
}

bool sys_remove(const char *filename)
{
  if (get_user(filename) == -1)
    handle_invalid_access();

  lock_acquire(&filesys_lock);
  bool return_value = filesys_remove(filename);
  lock_release(&filesys_lock);
  return return_value;
}

int sys_open(const char *my_filename)
{
  struct file *my_opened_file;
  struct file_desc *my_f_desc;
  if (get_user(my_filename) == -1)
    handle_invalid_access();

  lock_acquire(&filesys_lock);
  my_opened_file = filesys_open(my_filename);
  if (!my_opened_file)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  my_f_desc = malloc(sizeof(*my_f_desc));
  my_f_desc->file = my_opened_file;
  struct list *my_files_list = &thread_current()->file_descriptors;
  if (list_empty(my_files_list))
    my_f_desc->id = 2; /* 0=STDIN, 1=STDOUT */
  else
    my_f_desc->id = list_entry(list_back(my_files_list), struct file_desc, elem)->id + 1;
  list_push_back(my_files_list, &my_f_desc->elem);
  lock_release(&filesys_lock);

  return my_f_desc->id;
}

int sys_filesize(int file_descriptor)
{
  struct file_desc *file_desc_ptr = find_file_desc(file_descriptor);

  if (file_desc_ptr == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  int file_size = file_length(file_desc_ptr->file);
  lock_release(&filesys_lock);
  return file_size;
}

int sys_read(int fd, void *buf, unsigned nbytes)
{
  if (get_user((const uint8_t *)buf) == -1)
    handle_invalid_access();

  if (fd == 0)
  { // STDIN
    for (int i = 0; i < nbytes; i++)
      if (!put_user(buf + i, input_getc()))
        handle_invalid_access();
    return nbytes;
  }
  else
  {
    lock_acquire(&filesys_lock);
    struct file_desc *file_desc = find_file_desc(fd);

    if (file_desc && file_desc->file)
    {
      off_t bytes_read = file_read(file_desc->file, buf, nbytes);
      lock_release(&filesys_lock);
      return bytes_read;
    }
    else
    {
      lock_release(&filesys_lock);
      return -1;
    }
  }
}

int sys_write(int file_descriptor, const void *data_buffer, unsigned data_size)
{
  if (get_user((const uint8_t *)data_buffer) == -1)
    handle_invalid_access();

  if (file_descriptor == 1)
  {
    putbuf((const char *)data_buffer, data_size);
    return data_size;
  }
  else
  {
    lock_acquire(&filesys_lock);
    struct file_desc *file_desc = find_file_desc(file_descriptor);

    if (file_desc && file_desc->file)
    {
      off_t bytes_written = file_write(file_desc->file, data_buffer, data_size);
      lock_release(&filesys_lock);
      return bytes_written;
    }
    else
    {
      lock_release(&filesys_lock);
      return -1;
    }
  }
}

void sys_seek(int file_descriptor, unsigned new_position)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_desc = find_file_desc(file_descriptor);

  if (file_desc && file_desc->file)
  {
    file_seek(file_desc->file, new_position);
    lock_release(&filesys_lock);
  }
  else
  {
    lock_release(&filesys_lock);
    sys_exit(-1);
  }
}

unsigned sys_tell(int file_descriptor)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_desc_ptr = find_file_desc(file_descriptor);

  if (file_desc_ptr && file_desc_ptr->file)
  {
    off_t position = file_tell(file_desc_ptr->file);
    lock_release(&filesys_lock);
    return position;
  }
  else
  {
    lock_release(&filesys_lock);
    sys_exit(-1);
  }
}

void sys_close(int file_descriptor)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_descriptor_struct = find_file_desc(file_descriptor);

  if (file_descriptor_struct && file_descriptor_struct->file)
  {
    file_close(file_descriptor_struct->file);
    list_remove(&file_descriptor_struct->elem);
    free(file_descriptor_struct);
  }
  lock_release(&filesys_lock);
}

static struct file_desc *
find_file_desc(int fd)
{
  if (fd < 2)
    return NULL;

  struct thread *current_thread = thread_current();

  if (list_empty(&current_thread->file_descriptors))
    return NULL;

  struct list_elem *element;
  struct file_desc *found_file_desc = NULL;
  for (element = list_begin(&current_thread->file_descriptors); element != list_end(&current_thread->file_descriptors);
       element = list_next(element))
  {
    struct file_desc *file_descriptor =
        list_entry(element, struct file_desc, elem);
    if (file_descriptor->id == fd)
    {
      found_file_desc = file_descriptor;
      break;
    }
  }
  return found_file_desc;
}

/* Read IND argument from stack pointer in F and store at DEST. */
static void
read_from_stack(struct intr_frame *f, void *dest, int ind)
{
  mem_read(f->esp + ind * 4, dest, 4);
}

/* Reads BYTES bytes at SRC and stores at DEST.
   Returns number of bytes read if successful, -1 if a
   segfault occurred. */
static int
mem_read(void *src, void *dest, size_t bytes)
{
  int32_t value;
  for (size_t i = 0; i < bytes; i++)
  {
    value = get_user(src + i);
    if (value == -1)
      handle_invalid_access();
    *(char *)(dest + i) = value;
  }
  return (int)bytes;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
  if ((void *)uaddr >= PHYS_BASE)
    return -1;

  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  if ((void *)udst >= PHYS_BASE)
    return false;

  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}
