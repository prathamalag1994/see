#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"

struct process_info {
  tid_t pid;
  char name[256];
  int exit_code;

  struct list_elem elem;
};

struct file_open {		//----------------------------made a struct to handle all the files processes
  
  int fda;
  struct file *fp;
  struct list_elem elem;
};


void set_process_exitcode(tid_t pid, int exitcode) ;
struct process_info* get_process_info(tid_t pid) ;
void add_process_to_list(const char* name,  tid_t tid) ;
struct file* get_file (int fd);
void syscall_init (void);
void exit(int exit_code);

#endif /* userprog/syscall.h */

