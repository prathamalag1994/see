#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include <list.h>
#include <string.h>

static void syscall_handler (struct intr_frame *);

struct list process_info_list;

//Made a File descriptor list
struct list file_open_list;

static struct lock pil_lock;

//a global file discriptor variable
int fda=5;



bool check_ptr(void* ptr);

void exec(struct intr_frame *f, int* esp);
void wait (struct intr_frame *f, int* esp);
void create(struct intr_frame *f, int* esp);
void remove(struct intr_frame *f, int* esp);
void open(struct intr_frame *f, int* esp);
void filesize (struct intr_frame *f, int* esp);
void read(struct intr_frame *f, int* esp);
void write(struct intr_frame *f, int* esp);
void seek (struct intr_frame *f, int* esp);
void tell(struct intr_frame *f, int* esp);
void close(struct intr_frame *f, int* esp);

struct process_info* get_process_info(tid_t pid) {
  struct list_elem *e;

  struct process_info* pi = NULL;
  lock_acquire(&pil_lock);
  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
  {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
         pi = p;
         break;
      }
  }

  lock_release(&pil_lock);

  return pi;
}


void add_process_to_list(const char* name, tid_t tid) {
  struct process_info *pi  = (struct process_info*) malloc (sizeof(struct process_info));
  pi->exit_code = -1000;
  pi->pid = tid;
  memcpy(pi->name, name, strlen(name)+1);

  lock_acquire(&pil_lock);
  list_push_back(&process_info_list, &pi->elem);
  lock_release(&pil_lock);
}

void set_process_exitcode(tid_t pid, int exit_code) {
  struct list_elem *e;

  lock_acquire(&pil_lock);

  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
    {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        p->exit_code = exit_code;
        break;
      }
    }

  lock_release(&pil_lock);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&process_info_list);
  list_init(&file_open_list);
  lock_init(&pil_lock);
}

bool check_ptr(void* ptr) {
  struct thread* t = thread_current();
  if ( !is_user_vaddr (ptr) || pagedir_get_page(t->pagedir, ptr) == NULL) {
    return false;
  }
  return true;
}

void exit(int exit_code) {
  set_process_exitcode(thread_current()->tid, exit_code);
  struct process_info* pi = get_process_info(thread_current()->tid) ;

  printf("%s: exit(%d)\n", pi->name , exit_code);
  thread_exit();
} 

void write(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = (void *)(*(esp + 2));
  unsigned int len = *(esp + 3);

  if (!check_ptr( buffer )){
    exit(-1);
    return;
  }

  if (fd == STDIN_FILENO) {
    exit(-1);
    return;
  }

  else if (fd == STDOUT_FILENO) {
    putbuf(buffer, len);
    f->eax = len;
    return;
  }
	  lock_acquire(&pil_lock);
	  struct file *file = get_file(fd);
	  if (!file)
	    {
	      f->eax = -1;
	      lock_release(&pil_lock);
	      return;
	    }
	  int bytes = file_write(file, buffer, len);
	  lock_release(&pil_lock);
	  f->eax = bytes;
	  return;
  
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
 
  if ( !check_ptr(esp)) {
    exit(-1);
    return;
  }

  int number = *esp;
  if (number == 0) {
    shutdown_power_off();
  }
  else if (number == 1) {
    if ( !check_ptr(esp+1) ) {
      exit(-1);
      return;
    }
    int exit_code = *(esp+1) ;
    exit(exit_code);
  }
  else if (number == SYS_WRITE) {
    write(f, esp);
  }
  else if (number == SYS_CREATE) {
    create(f, esp);
  }
  else if (number == SYS_OPEN) {
    open(f, esp);
  }
  else if (number == SYS_CLOSE) {
    close(f, esp);
  }
  else if (number == SYS_READ) {
    read(f, esp);
  }
  else if (number == SYS_WAIT) {
    wait(f,esp);
  }
  else if (number == SYS_EXEC) {
    exec(f, esp);
  }
  else if (number == SYS_FILESIZE) {
    filesize(f, esp);
  }
  else if (number == SYS_TELL) {
    tell(f, esp);
  }
  else if (number == SYS_SEEK) {
    seek(f, esp);
  }
  else if (number == SYS_REMOVE) {
    remove(f, esp);
  }

}


void create(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }

  char* buffer = (char *)(*(esp + 1));
  unsigned int size = *(esp + 2);

 if (strlen(buffer) == 0) {
    f->eax = 0;
    return;
  }
  else {
    f->eax = filesys_create(buffer, size);
    return;
  }
return;
}


void open(struct intr_frame *f, int* esp) {
  
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }

  void* buffer = (void *)(*(esp + 2));

 if (strlen(buffer) == 0) {
    f->eax = 0 ;
    return;
  }

	lock_acquire(&pil_lock);
	struct file *files = filesys_open ((const char *)*(esp + 1));
	
  	if (!files) {
		
		f->eax = -1;
		lock_release(&pil_lock);
		return;
  	}  
	
	  struct file_open *f_elem = (struct file_open *) malloc (sizeof (struct file_open));
	  ASSERT(f_elem);

		  f_elem->fda =fda++;
		  f_elem->fp = files;
		  f->eax = f_elem->fda;
		  list_push_back (&file_open_list, &f_elem->elem);
		  lock_release(&pil_lock);

}

void close(struct intr_frame *f UNUSED, int* esp) {
  
  
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  int fd = *(esp + 1);

  struct list_elem *e;
  lock_acquire(&pil_lock);
  for (e = list_begin (&file_open_list); e != list_end (&file_open_list);
       e = list_next (e))
    {
      struct file_open *f_elem = list_entry (e, struct file_open, elem);
      if (f_elem->fda == fd)
	{
	  file_close (f_elem->fp);
	  list_remove (e);
	  free (f_elem);
          lock_release(&pil_lock);
	  return;
	}
    }
  
  lock_release(&pil_lock);
return;
}


void read(struct intr_frame *f, int* esp){
  
if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = (void *)(*(esp + 2));
  unsigned int len = *(esp + 3);

if (!check_ptr( buffer )){
    exit(-1);
    return;
  }

if (fd == STDOUT_FILENO) {
    exit(-1);
    return;
  }

 else if (fd == STDIN_FILENO)
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < len; i++)
	{
	  local_buffer[i] = input_getc();
	}
      f->eax = len;
      return;
    }

  lock_acquire(&pil_lock);
  struct file *file = get_file(fd);
  if (!file)
    {
      		f->eax = -1;
		lock_release(&pil_lock);
		return;
    }

  int bytes = file_read(file, buffer, len);
  lock_release(&pil_lock);
	
  f->eax = bytes; 
return;
}

void filesize (struct intr_frame *f, int* esp)
{
if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  lock_acquire(&pil_lock);
  struct file *file = get_file(fd);
  if (!file)
    {
      f->eax = -1;
      lock_release(&pil_lock);
      return;
    }
  int size = file_length(file);
  lock_release(&pil_lock);
  f->eax = size;
return;
}

void
tell (struct intr_frame *f, int* esp)
{
 if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  lock_acquire(&pil_lock);
  struct file *file = get_file(fd);
  if (!file)
    {
      f->eax = -1;
      lock_release(&pil_lock);
      return;
    }
int size = file_tell (file);
  lock_release(&pil_lock);
  f->eax = size;
return;
}

void
seek (struct intr_frame *f, int* esp)
{
  if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  lock_acquire(&pil_lock);
  struct file *file = get_file(fd);
  if (!file)
    {
      f->eax = -1;
      lock_release(&pil_lock);
      return;
    }
  file_seek (file, (unsigned)*(esp+2));
  lock_release(&pil_lock);
return;
}

void
remove (struct intr_frame *f, int* esp)
{
if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);

  lock_acquire(&pil_lock);
  struct file *file = get_file(fd);
  if (!file)
    {
      f->eax = -1;
      lock_release(&pil_lock);
      return;
    }
int size = filesys_remove ((const char *) file);
  lock_release(&pil_lock);
  f->eax = size;
return;
}

struct file* get_file (int fd)
{
  struct list_elem *e;

  for (e = list_begin (&file_open_list); e != list_end (&file_open_list);
       e = list_next (e))
        {
          struct file_open *f_elem = list_entry (e, struct file_open, elem);
          if (fd == f_elem->fda)
	    {
		  return f_elem->fp;
	    }
        }
  return NULL;
}


void exec(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    f->eax = -1;
    exit(-1);
  }
  
  char* fd = (char *)(*(esp + 1));
  
  if (strlen(fd) == 0) {
    f->eax = -1;
    return;
  }
  
  char *savePtr;
  char* filename = palloc_get_page(0);
  strlcpy (filename, fd, PGSIZE);
  char *exename = strtok_r ((char *)filename, " ", &savePtr);
  struct file *file = filesys_open(exename);

  if(!file){
    f->eax = -1;
    return;
  }


  f->eax = process_execute(fd);
return;
}

void wait (struct intr_frame *f,int* esp)
{
if ( !check_ptr(esp+1)  ) {
    exit(-1);
    return;
  }

  f->eax = process_wait(*(esp + 1));
return;
}

