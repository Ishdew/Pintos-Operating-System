#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void start_process(void *arg);
static bool load(const char *cmdline, void (**eip)(void), void **esp);
static void push_args_to_stack(char **args, int argc, void **esp);

pid_t process_execute(const char *file_name)
{
  char *file_name_copy = NULL;
  char *program_name = NULL;
  struct process_control_block *pcb = NULL;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise, there's a race between the caller and load(). */
  file_name_copy = palloc_get_page(0);
  if (file_name_copy == NULL)
    goto process_execute_error;
  strlcpy(file_name_copy, file_name, PGSIZE);

  /* Make an additional copy to store just the program name */
  char *save_ptr = NULL;
  program_name = palloc_get_page(0);
  if (program_name == NULL)
    goto process_execute_error;
  strlcpy(program_name, file_name, PGSIZE);
  program_name = strtok_r(program_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  pcb = palloc_get_page(0);
  if (pcb == NULL)
    goto process_execute_error;

  /* Initialize PCB */
  pcb->pid = -2;
  pcb->command = file_name_copy;
  pcb->waiting = false;
  pcb->exited = false;
  pcb->exit_code = -1;
  sema_init(&pcb->waiting_sema, 0);
  sema_init(&pcb->initialization_sema, 0);

  tid = thread_create(program_name, PRI_DEFAULT, start_process, pcb);

  if (tid == TID_ERROR)
    goto process_execute_error;

  sema_down(&pcb->initialization_sema);

  palloc_free_page(file_name_copy);
  palloc_free_page(program_name);

  if (pcb->pid >= 0) /* Executable successfully loaded */
    list_push_back(&thread_current()->child_list, &pcb->elem);
  return pcb->pid;

process_execute_error:
  if (file_name_copy)
    palloc_free_page(file_name_copy);
  if (program_name)
    palloc_free_page(program_name);
  if (pcb)
    palloc_free_page(pcb);

  return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *pcb_)
{
  struct process_control_block *pcb = pcb_;
  char *command = pcb->command;
  struct intr_frame intr_frame_;
  bool load_success;
  struct thread *current_thread;

  /* Tokenize command */
  char *token, *token_save_ptr;
  char **arguments = palloc_get_page(0);
  if (arguments == NULL)
    goto start_process_finished;
  int argument_count = 0;
  for (token = strtok_r(command, " ", &token_save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &token_save_ptr))
  {
    arguments[argument_count++] = token;
  }

  /* Initialize interrupt frame and load executable. */
  memset(&intr_frame_, 0, sizeof intr_frame_);
  intr_frame_.gs = intr_frame_.fs = intr_frame_.es = intr_frame_.ds = intr_frame_.ss = SEL_UDSEG;
  intr_frame_.cs = SEL_UCSEG;
  intr_frame_.eflags = FLAG_IF | FLAG_MBS;
  load_success = load(command, &intr_frame_.eip, &intr_frame_.esp);

  if (load_success)
    push_args_to_stack(arguments, argument_count, &intr_frame_.esp);

  palloc_free_page(arguments);

start_process_finished:

  current_thread = thread_current();
  pcb->pid = load_success ? (pid_t)current_thread->tid : (pid_t)-1;
  current_thread->pcb = pcb;

  sema_up(&pcb->initialization_sema);

  /* If load failed, quit. */
  if (!load_success)
    sys_exit(-1);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&intr_frame_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid)
{
  /* Find child process */
  struct process_control_block *child_pcb = NULL;
  struct list *child_list = &thread_current()->child_list;
  struct list_elem *child_elem;
  if (!list_empty(child_list))
  {
    for (child_elem = list_begin(child_list); child_elem != list_end(child_list);
         child_elem = list_next(child_elem))
    {
      struct process_control_block *child_pcb_temp =
          list_entry(child_elem, struct process_control_block, elem);
      if (child_pcb_temp->pid == child_tid)
      {
        child_pcb = child_pcb_temp;
        break;
      }
    }
  }

  /* Return -1 if not a direct child process */
  if (child_pcb == NULL)
    return -1;

  /* Return -1 if called twice */
  if (child_pcb->waiting)
    return -1;
  else
    child_pcb->waiting = true;

  /* Wait for the child process and retrieve exit status */
  if (!child_pcb->exited)
    sema_down(&child_pcb->waiting_sema);
  ASSERT(child_pcb->exited == true);

  list_remove(child_elem);

  int exit_code = child_pcb->exit_code;
  palloc_free_page(child_pcb);
  return exit_code;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *current_thread = thread_current();
  uint32_t *page_directory;

  /* Close all opened files and free memory */
  struct list *file_descriptors_list = &current_thread->file_descriptors;
  struct file_desc *file_descriptor;
  while (!list_empty(file_descriptors_list))
  {
    file_descriptor = list_entry(list_pop_front(file_descriptors_list), struct file_desc, elem);
    file_close(file_descriptor->file);
    free(file_descriptor);
  }

  /* Free process control blocks of all child processes */
  struct list *child_list = &current_thread->child_list;
  struct process_control_block *child_pcb;
  while (!list_empty(child_list))
  {
    child_pcb = list_entry(list_pop_front(child_list), struct process_control_block, elem);
    palloc_free_page(child_pcb);
  }

  sema_up(&current_thread->pcb->waiting_sema);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  page_directory = current_thread->pagedir;
  if (page_directory != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       current_thread->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    current_thread->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(page_directory);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *current_thread = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(current_thread->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**entry_point)(void), void **stack_pointer)
{
  struct thread *cur_thread = thread_current();
  struct Elf32_Ehdr header;
  struct file *executable_file = NULL;
  off_t offset;
  bool load_success = false;
  int i;

  /* Allocate and activate page directory. */
  cur_thread->pagedir = pagedir_create();
  if (cur_thread->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  executable_file = filesys_open(file_name);
  if (executable_file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(executable_file, &header, sizeof header) != sizeof header || memcmp(header.e_ident, "\177ELF\1\1\1", 7) || header.e_type != 2 || header.e_machine != 3 || header.e_version != 1 || header.e_phentsize != sizeof(struct Elf32_Phdr) || header.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  offset = header.e_phoff;
  for (i = 0; i < header.e_phnum; i++)
  {
    struct Elf32_Phdr program_header;

    if (offset < 0 || offset > file_length(executable_file))
      goto done;
    file_seek(executable_file, offset);

    if (file_read(executable_file, &program_header, sizeof program_header) != sizeof program_header)
      goto done;
    offset += sizeof program_header;
    switch (program_header.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&program_header, executable_file))
      {
        bool writable = (program_header.p_flags & PF_W) != 0;
        uint32_t file_page = program_header.p_offset & ~PGMASK;
        uint32_t mem_page = program_header.p_vaddr & ~PGMASK;
        uint32_t page_offset = program_header.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (program_header.p_filesz > 0)
        {
          /* Normal segment.
             Read the initial part from the disk and zero the rest. */
          read_bytes = page_offset + program_header.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + program_header.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from the disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + program_header.p_memsz, PGSIZE);
        }
        if (!load_segment(executable_file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up the stack. */
  if (!setup_stack(stack_pointer))
    goto done;

  /* Start address. */
  *entry_point = (void (*)(void))header.e_entry;

  load_success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(executable_file);
  return load_success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *segment_header, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((segment_header->p_offset & PGMASK) != (segment_header->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (segment_header->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (segment_header->p_memsz < segment_header->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (segment_header->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)segment_header->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(segment_header->p_vaddr + segment_header->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (segment_header->p_vaddr + segment_header->p_memsz < segment_header->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (segment_header->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t offset, uint8_t *user_page,
             uint32_t bytes_to_read, uint32_t bytes_to_zero, bool is_writable)
{
  ASSERT((bytes_to_read + bytes_to_zero) % PGSIZE == 0);
  ASSERT(pg_ofs(user_page) == 0);
  ASSERT(offset % PGSIZE == 0);

  file_seek(file, offset);
  while (bytes_to_read > 0 || bytes_to_zero > 0)
  {
    size_t page_read_bytes = bytes_to_read < PGSIZE ? bytes_to_read : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    uint8_t *kernel_page = palloc_get_page(PAL_USER);
    if (kernel_page == NULL)
      return false;

    if (file_read(file, kernel_page, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kernel_page);
      return false;
    }
    memset(kernel_page + page_read_bytes, 0, page_zero_bytes);

    if (!install_page(user_page, kernel_page, is_writable))
    {
      palloc_free_page(kernel_page);
      return false;
    }

    bytes_to_read -= page_read_bytes;
    bytes_to_zero -= page_zero_bytes;
    user_page += PGSIZE;
  }
  return true;
}
/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **custom_esp)
{
  uint8_t *custom_kpage;
  bool custom_success = false;

  custom_kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (custom_kpage != NULL)
  {
    custom_success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, custom_kpage, true);
    if (custom_success)
      *custom_esp = PHYS_BASE;
    else
      palloc_free_page(custom_kpage);
  }
  return custom_success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *user_page, void *kernel_page, bool is_writable)
{
  struct thread *current_thread = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(current_thread->pagedir, user_page) == NULL && pagedir_set_page(current_thread->pagedir, user_page, kernel_page, is_writable));
}

/* Setup stack at ESP with ARGC arguments from ARGS array. */
static void push_args_to_stack(char **arguments, int arg_count, void **esp)
{
  /* Arguments last to first, top to bottom */
  int length;
  int arg_addresses[arg_count];
  for (int i = arg_count - 1; i >= 0; i--)
  {
    length = strlen(arguments[i]) + 1;
    *esp -= length;
    memcpy(*esp, arguments[i], length);
    arg_addresses[i] = (int)*esp;
  }

  /* Word align */
  *esp = (void *)((int)*esp & 0xfffffffc);

  /* Null */
  *esp -= 4;
  *(int *)*esp = 0;

  /* Addresses to arguments last to first, top to bottom */
  for (int i = arg_count - 1; i >= 0; i--)
  {
    *esp -= 4;
    *(int *)*esp = arg_addresses[i];
  }

  /* Address to first argument */
  *esp -= 4;
  *(int *)*esp = (int)*esp + 4;

  /* argc */
  *esp -= 4;
  *(int *)*esp = arg_count;

  /* Return address (0) */
  *esp -= 4;
  *(int *)*esp = 0;
}
