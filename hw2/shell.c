#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens *tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc
{
  cmd_fun_t *fun;
  char *cmd;
  char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_cd, "cd", "change active directory"},
    {cmd_pwd, "pwd", "print current directory"},

};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens *tokens)
{
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens *tokens)
{
  exit(0);
}

int cmd_cd(struct tokens *tokens)
{
  chdir(tokens_get_token(tokens, 1));
  return 1;
}

int cmd_pwd(struct tokens *tokens)
{
  char *dir = get_current_dir_name();
  printf("%s\n", dir);
  free(dir);
  return 1;
}

void redirect_input_output(struct tokens *tokens)
{
  for (int i = 0; i < tokens->tokens_length; i++)
  {
    if(tokens->tokens[i] == 0)  continue;
    if (tokens->tokens[i][0] == '>')
    {
      freopen(tokens->tokens[i + 1], "w", stdout);
      free(tokens->tokens[i]);
      tokens->tokens[i] = 0;
    }
    else if (tokens->tokens[i][0] == '<')
    {
      freopen(tokens->tokens[i + 1], "r", stdin);

      free(tokens->tokens[i]);
      tokens->tokens[i] = 0;
    }
  }
}

void dump_tokens(char** tokens)
{
  int i ;
  while(tokens[i])
    printf("%s ", tokens[i++]);
  printf("\n");
}

//this signal hander first transfers terminal to parent pg and then goes through default handler
void sig_transer_parent(int signo) {
  tcsetpgrp(STDIN_FILENO, getppid());
  if(signo == SIGTSTP)  signo = SIGINT;
  signal(signo, SIG_DFL);
  // printf("raising %d\n", signo);
  raise(signo);
}


int cmd_custom_program(struct tokens *tokens)
{

  const char *path_orig = getenv("PATH");
  sep = ':';
  struct tokens *tokens_path = tokenize(path_orig);
  sep = ' ';

  int pid = fork();
  int ret;

  if (pid == 0)
  {
    signal(SIGINT, sig_transer_parent);
    signal(SIGQUIT, sig_transer_parent);
    signal(SIGTSTP, sig_transer_parent);

    pid = fork();
    if(pid==0)
    {
      int pipes[2];
      // int pipes_old[2];
      // dump_tokens(tokens->tokens);
      for (int j = 0; j < tokens->tokens_length; )
      {
        // pipes_old[0] = pipes[0], pipes_old[1] = pipes[1];
        int k = j;
        
        for (; k < tokens->tokens_length; k++)
          if (tokens->tokens[k][0] == '|')
            break;

        // printf("Found k: %d vs %d\n", k, tokens->tokens_length);
        if (k !=tokens->tokens_length)
        {
          // printf("rerouting\n");
          
          pipe(pipes);
          pid = fork();
          if(!pid)
            dup2(pipes[1], STDOUT_FILENO), close(pipes[0]);
          else
            dup2(pipes[0], STDIN_FILENO), close(pipes[1]);
        }
        else
          pid = 0;

        if(!pid)
        {
          // signal(SIGINT, SIG_DFL);
          // setpgid(0, 0);
          tokens->tokens[k] = 0;
          redirect_input_output(tokens);

          char *prefix = get_current_dir_name();
          int i = 0;
          do
          {
            int len = strlen(prefix) + strlen(tokens->tokens[j]) + 2;
            char *temp = malloc(len);
            strcpy(temp, prefix);
            temp[strlen(prefix)] = '/';
            strcpy(temp + strlen(prefix) + 1, tokens->tokens[j]);
            execv(temp, tokens->tokens+j);

            int err = errno;
            if (err != ENOENT)
            {
              printf("Error while launching: %d, %s\n", err, temp);
              exit(0);
            }

            if (i == 0)
              free(prefix);
            free(temp);
          } while ((prefix = tokens_path->tokens[i++]));
          printf("Error: No such executable or command found! %s\n", prefix);
          exit(0);
        }
        else
        {
          // setpgid(pid, pid);
          // tcsetpgrp(STDIN_FILENO, pid);
          wait(&ret);
        }

        j = k+1;
      }
      // while (1) {
      //   int ch = fgetc(stdin);
      //   if(ch == EOF) break;
      //   printf("%c", ch);
      // }

      exit(0);
    }
    else
    {

      wait(&ret);
      tcsetpgrp(STDIN_FILENO, getppid());
      
      exit(0);
    }
  }
  setpgid(pid, pid);
  // signal(SIGINT, SIG_IGN);
  // signal(SIGTTOU, SIG_IGN);

  tcsetpgrp(STDIN_FILENO, pid);
  // signal(SIGINT, SIG_IGN);

  wait(&ret);
  // while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
  //   kill(-shell_pgid, SIGTTIN);


  tokens_destroy(tokens_path);

  return 1;
}
void sig(int signo) {
    const char* msg = strsignal(signo); // XXX: Not async-signal-safe.
    write(STDOUT_FILENO, msg, strlen(msg));
    write(STDOUT_FILENO, "\n", 1);
}


/* Looks up the built-in command, if it exists. */
int lookup(char cmd[])
{
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* Intialization procedures for this shell */
void init_shell()
{

  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGTSTP, SIG_IGN);

  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive)
  {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
  }
}

int main(unused int argc, unused char *argv[])
{
  init_shell();
  sep = ' ';
  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin))
  {
    /* Split our line into words. */
    struct tokens *tokens = tokenize(line);

    /* Find which built-in function to run. */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0)
    {
      cmd_table[fundex].fun(tokens);
    }
    else
    {
      /* REPLACE this to run commands as programs. */
      cmd_custom_program(tokens);
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}
