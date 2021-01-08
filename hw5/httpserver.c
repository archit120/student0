#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

#include "libhttp.h"
#include "wq.h"

#include "errd.h"

#define POOLSERVER

int is_regular_file(const char *path)
{
  struct stat path_stat;
  stat(path, &path_stat);
  return S_ISREG(path_stat.st_mode);
}

/*
 * Global configuration variables.
 * You need to use these in your implementation of handle_files_request and
 * handle_proxy_request. Their values are set up in main() using the
 * command line arguments (already implemented for you).
 */
wq_t work_queue; // Only used by poolserver
int num_threads; // Only used by poolserver
int server_port; // Default value: 8000
char *server_files_directory;
char *server_proxy_hostname;
int server_proxy_port;

/*
 * Serves the contents the file stored at `path` to the client socket `fd`.
 * It is the caller's reponsibility to ensure that the file stored at `path` exists.
 */
void serve_file(int fd, char *path)
{

  /* TODO: PART 2 */
  /* PART 2 BEGIN */

  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(path));

  int file_fd = open(path, O_RDONLY);

  int sz = 0;
  int cur = 0;
  char buffer[100];
  // printf("%d", file_fd);
  while ((cur = read(file_fd, buffer, 100)))
    sz += cur;
  // printf(" ");
  // printf("%d", sz);

  lseek(file_fd, 0, SEEK_SET);
  sprintf(buffer, "%d", sz);

  http_send_header(fd, "Content-Length", buffer); // TODO: change this line too
  http_end_headers(fd);

  while ((cur = read(file_fd, buffer, 100)))
  {
    int written = 0;
    while (written < cur)
    {
      written += write(fd, buffer + written, cur - written);
    }
  }

  close(file_fd);
  /* PART 2 END */
}

void serve_directory(int fd, char *path)
{
  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(".html"));
  http_end_headers(fd);

  /* TODO: PART 3 */
  /* PART 3 BEGIN */

  // TODO: Open the directory (Hint: opendir() may be useful here)

  /**
   * TODO: For each entry in the directory (Hint: look at the usage of readdir() ),
   * send a string containing a properly formatted HTML. (Hint: the http_format_href()
   * function in libhttp.c may be useful here)
   */

  //insert after 16 chars
  const char *header = "<html>\n<body>\n";
  const char *footer = "</body>\n</html>\n";

  char *data_buf = malloc(400);
  strcpy(data_buf, header);
  int pt = 14;
  int sz = 400;
  DIR *d;
  struct dirent *dir;
  d = opendir(path);
  path[strlen(path) - 1] = '\0';
  while ((dir = readdir(d)) != NULL)
  {
    if (sz - pt < 200)
      data_buf = realloc(data_buf, sz + 400), sz += 400;
    pt += http_format_href(data_buf + pt, path, dir->d_name);
    data_buf[pt - 1] = '\n';
    // printf("%s\n", dir->d_name);
  }
  closedir(d);
  if (sz - pt < 20)
    data_buf = realloc(data_buf, sz + 400), sz += 400;

  memcpy(data_buf + pt, footer, 17);
  int len = strlen(data_buf);
  // printf("%s\n", data_buf);

  int written = 0;
  while (written < len)
  {
    written += write(fd, data_buf + written, len - written);
  }

  free(data_buf);

  /* PART 3 END */
}

/*
 * Reads an HTTP request from client socket (fd), and writes an HTTP response
 * containing:
 *
 *   1) If user requested an existing file, respond with the file
 *   2) If user requested a directory and index.html exists in the directory,
 *      send the index.html file.
 *   3) If user requested a directory and index.html doesn't exist, send a list
 *      of files in the directory with links to each.
 *   4) Send a 404 Not Found response.
 *
 *   Closes the client socket (fd) when finished.
 */
void handle_files_request(int fd)
{
  struct http_request *request = http_request_parse(fd);

  if (request == NULL || request->path[0] != '/')
  {
    http_start_response(fd, 400);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  if (strstr(request->path, "..") != NULL)
  {
    http_start_response(fd, 403);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  /* Remove beginning `./` */
  char *path = malloc(2 + strlen(request->path) + 1);
  path[0] = '.';
  path[1] = '/';
  memcpy(path + 2, request->path + 1, strlen(request->path));

  /*
   * TODO: PART 2 is to serve files. If the file given by `path` exists,
   * call serve_file() on it. Else, serve a 404 Not Found error below.
   * The `stat()` syscall will be useful here.
   *
   * TODO: PART 3 is to serve both files and directories. You will need to
   * determine when to call serve_file() or serve_directory() depending
   * on `path`. Make your edits below here in this function.
   */

  /* PART 2 & 3 BEGIN */
  // printf("\n%s\n", path);
  if (access(path, F_OK) == 0)
  {
    if (!is_regular_file(path))
    {
      char *path2 = malloc(strlen(path) + 11);
      int sz = strlen(path);
      strcpy(path2, path);
      strcat(path2 + sz, "index.html");
      if (access(path2, F_OK) == 0)
        serve_file(fd, path2);
      else
        serve_directory(fd, path);
      free(path2);
    }
    else
      serve_file(fd, path);
    free(path);
  }
  else
  {

    http_start_response(fd, 404);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  /* PART 2 & 3 END */

  close(fd);
  return;
}

struct proxy_sockets
{
  int sender_fd;
  int receiver_fd;
  char* descriptor;
  pthread_t *thread_other;
};

void *proxy_connect(void *arg)
{
  struct proxy_sockets *p = (struct proxy_sockets *)arg;
  int read_bytes;
  char buffer[1000];
  // printf("in1\n");
  // pthread_setcanceltype()
  while (1)
  {
    read_bytes = read(p->receiver_fd, buffer, 1000);
    // printf("Read:%d\n", read_bytes);
    if (read_bytes == -1 || read_bytes == 0)
    {
      // printf("Closing from error %s \n", errnoname(errno));
      // close the other socket
      // this can be an error but we can ignore
      close(p->sender_fd);
      close(p->receiver_fd);
      // printf(" calling pthread_cancel %s \n", errnoname(errno));
      // shutdown(p->sender_fd, SHUT_RDWR);.
      pthread_cancel(*(p->thread_other));
      return NULL;
    }
    int sent_bytes = 0;
    while (sent_bytes != read_bytes)
    {
      int tsend = write(p->sender_fd, buffer + sent_bytes, read_bytes - sent_bytes);
      if (tsend == -1)
      {
        // printf("Closing2 from error %s \n", errnoname(errno));
        // close the other socket
        // this can be an error but we can ignore
        close(p->sender_fd);
        close(p->receiver_fd);
        pthread_cancel(*(p->thread_other));
        return NULL;
      }
      sent_bytes += tsend;
    }
  }
  return NULL;
}

/*
 * Opens a connection to the proxy target (hostname=server_proxy_hostname and
 * port=server_proxy_port) and relays traffic to/from the stream fd and the
 * proxy target_fd. HTTP requests from the client (fd) should be sent to the
 * proxy target (target_fd), and HTTP responses from the proxy target (target_fd)
 * should be sent to the client (fd).
 *
 *   +--------+     +------------+     +--------------+
 *   | client | <-> | httpserver | <-> | proxy target |
 *   +--------+     +------------+     +--------------+
 *
 *   Closes client socket (fd) and proxy target fd (target_fd) when finished.
 */
void handle_proxy_request(int fd)
{

  /*
  * The code below does a DNS lookup of server_proxy_hostname and
  * opens a connection to it. Please do not modify.
  */
  struct sockaddr_in target_address;
  memset(&target_address, 0, sizeof(target_address));
  target_address.sin_family = AF_INET;
  target_address.sin_port = htons(server_proxy_port);

  // Use DNS to resolve the proxy target's IP address
  struct hostent *target_dns_entry = gethostbyname2(server_proxy_hostname, AF_INET);

  // Create an IPv4 TCP socket to communicate with the proxy target.
  int target_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (target_fd == -1)
  {
    fprintf(stderr, "Failed to create a new socket: error %d: %s\n", errno, strerror(errno));
    close(fd);
    exit(errno);
  }

  if (target_dns_entry == NULL)
  {
    fprintf(stderr, "Cannot find host: %s\n", server_proxy_hostname);
    close(target_fd);
    close(fd);
    exit(ENXIO);
  }

  char *dns_address = target_dns_entry->h_addr_list[0];

  // Connect to the proxy target.
  memcpy(&target_address.sin_addr, dns_address, sizeof(target_address.sin_addr));
  int connection_status = connect(target_fd, (struct sockaddr *)&target_address,
                                  sizeof(target_address));

  if (connection_status < 0)
  {
    /* Dummy request parsing, just to be compliant. */
    http_request_parse(fd);

    http_start_response(fd, 502);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(target_fd);
    close(fd);
    return;
  }

  /* TODO: PART 4 */
  /* PART 4 BEGIN */
  struct proxy_sockets data[2];
  data[0].receiver_fd = data[1].sender_fd = fd;
  data[0].sender_fd = data[1].receiver_fd = target_fd;

  pthread_t threads[2];

  data[0].thread_other = threads + 1;
  data[1].thread_other = threads;
  pthread_create(threads, NULL, &proxy_connect, (void *)data);
  pthread_create(threads + 1, NULL, &proxy_connect, (void *)(data + 1));

  pthread_join(threads[0], NULL);

  // printf("READY\n");
  /* PART 4 END */
}

#ifdef POOLSERVER
/*
 * All worker threads will run this function until the server shutsdown.
 * Each thread should block until a new request has been received.
 * When the server accepts a new connection, a thread should be dispatched
 * to send a response to the client.
 */
void *handle_clients(void *void_request_handler)
{
  void (*request_handler)(int) = (void (*)(int))void_request_handler;
  /* (Valgrind) Detach so thread frees its memory on completion, since we won't
   * be joining on it. */
  pthread_detach(pthread_self());

  /* TODO: PART 7 */
  /* PART 7 BEGIN */

  /* PART 7 END */
}

/*
 * Creates `num_threads` amount of threads. Initializes the work queue.
 */
void init_thread_pool(int num_threads, void (*request_handler)(int))
{

  /* TODO: PART 7 */
  /* PART 7 BEGIN */

  /* PART 7 END */
}
#endif

/*
 * Opens a TCP stream socket on all interfaces with port number PORTNO. Saves
 * the fd number of the server socket in *socket_number. For each accepted
 * connection, calls request_handler with the accepted fd number.
 */
void serve_forever(int *socket_number, void (*request_handler)(int))
{

  struct sockaddr_in server_address, client_address;
  size_t client_address_length = sizeof(client_address);
  int client_socket_number;

  // Creates a socket for IPv4 and TCP.
  *socket_number = socket(PF_INET, SOCK_STREAM, 0);
  if (*socket_number == -1)
  {
    perror("Failed to create a new socket");
    exit(errno);
  }

  int socket_option = 1;
  if (setsockopt(*socket_number, SOL_SOCKET, SO_REUSEADDR, &socket_option,
                 sizeof(socket_option)) == -1)
  {
    perror("Failed to set socket options");
    exit(errno);
  }

  // Setup arguments for bind()
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = INADDR_ANY;
  server_address.sin_port = htons(server_port);

  /*
   * TODO: PART 1
   *
   * Given the socket created above, call bind() to give it
   * an address and a port. Then, call listen() with the socket.
   * An appropriate size of the backlog is 1024, though you may
   * play around with this value during performance testing.
   */

  /* PART 1 BEGIN */

  if (bind(*socket_number, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
  {
    perror("Failed to bind to port");
    exit(errno);
  }

  if (listen(*socket_number, 1024) == -1)
  {
    perror("Failed to listen");
    exit(errno);
  }

  /* PART 1 END */
  printf("Listening on port %d...\n", server_port);

#ifdef POOLSERVER
  /*
   * The thread pool is initialized *before* the server
   * begins accepting client connections.
   */
  init_thread_pool(num_threads, request_handler);
#endif

  while (1)
  {
    client_socket_number = accept(*socket_number,
                                  (struct sockaddr *)&client_address,
                                  (socklen_t *)&client_address_length);
    if (client_socket_number < 0)
    {
      perror("Error accepting socket");
      continue;
    }

    printf("Accepted connection from %s on port %d\n",
           inet_ntoa(client_address.sin_addr),
           client_address.sin_port);

#ifdef BASICSERVER
    /*
     * This is a single-process, single-threaded HTTP server.
     * When a client connection has been accepted, the main
     * process sends a response to the client. During this
     * time, the server does not listen and accept connections.
     * Only after a response has been sent to the client can
     * the server accept a new connection.
     */
    request_handler(client_socket_number);

#elif FORKSERVER
    /*
     * TODO: PART 5
     *
     * When a client connection has been accepted, a new
     * process is spawned. This child process will send
     * a response to the client. Afterwards, the child
     * process should exit. During this time, the parent
     * process should continue listening and accepting
     * connections.
     */

    /* PART 5 BEGIN */
    if(!fork() )
    {
      request_handler(client_socket_number);
      close(*socket_number);
      return;
    }
    else
      close(client_socket_number);
    /* PART 5 END */

#elif THREADSERVER
    /*
     * TODO: PART 6
     *
     * When a client connection has been accepted, a new
     * thread is created. This thread will send a response
     * to the client. The main thread should continue
     * listening and accepting connections. The main
     * thread will NOT be joining with the new thread.
     */

    /* PART 6 BEGIN */
    pthread_t temp;
    pthread_create(&temp, NULL, request_handler, (void*)client_socket_number);
    /* PART 6 END */
#elif POOLSERVER
    /*
     * TODO: PART 7
     *
     * When a client connection has been accepted, add the
     * client's socket number to the work queue. A thread
     * in the thread pool will send a response to the client.
     */

    /* PART 7 BEGIN */

    /* PART 7 END */
#endif
  }

  shutdown(*socket_number, SHUT_RDWR);
  close(*socket_number);
}

int server_fd;
void signal_callback_handler(int signum)
{
  printf("Caught signal %d: %s\n", signum, strsignal(signum));
  printf("Closing socket %d\n", server_fd);
  if (close(server_fd) < 0)
    perror("Failed to close server_fd (ignoring)\n");
  exit(0);
}

char *USAGE =
    "Usage: ./httpserver --files some_directory/ [--port 8000 --num-threads 5]\n"
    "       ./httpserver --proxy inst.eecs.berkeley.edu:80 [--port 8000 --num-threads 5]\n";

void exit_with_usage()
{
  fprintf(stderr, "%s", USAGE);
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
  signal(SIGINT, signal_callback_handler);
  signal(SIGPIPE, SIG_IGN);

  /* Default settings */
  server_port = 8000;
  void (*request_handler)(int) = NULL;

  int i;
  for (i = 1; i < argc; i++)
  {
    if (strcmp("--files", argv[i]) == 0)
    {
      request_handler = handle_files_request;
      server_files_directory = argv[++i];
      if (!server_files_directory)
      {
        fprintf(stderr, "Expected argument after --files\n");
        exit_with_usage();
      }
    }
    else if (strcmp("--proxy", argv[i]) == 0)
    {
      request_handler = handle_proxy_request;

      char *proxy_target = argv[++i];
      if (!proxy_target)
      {
        fprintf(stderr, "Expected argument after --proxy\n");
        exit_with_usage();
      }

      char *colon_pointer = strchr(proxy_target, ':');
      if (colon_pointer != NULL)
      {
        *colon_pointer = '\0';
        server_proxy_hostname = proxy_target;
        server_proxy_port = atoi(colon_pointer + 1);
      }
      else
      {
        server_proxy_hostname = proxy_target;
        server_proxy_port = 80;
      }
    }
    else if (strcmp("--port", argv[i]) == 0)
    {
      char *server_port_string = argv[++i];
      if (!server_port_string)
      {
        fprintf(stderr, "Expected argument after --port\n");
        exit_with_usage();
      }
      server_port = atoi(server_port_string);
    }
    else if (strcmp("--num-threads", argv[i]) == 0)
    {
      char *num_threads_str = argv[++i];
      if (!num_threads_str || (num_threads = atoi(num_threads_str)) < 1)
      {
        fprintf(stderr, "Expected positive integer after --num-threads\n");
        exit_with_usage();
      }
    }
    else if (strcmp("--help", argv[i]) == 0)
    {
      exit_with_usage();
    }
    else
    {
      fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
      exit_with_usage();
    }
  }

  if (server_files_directory == NULL && server_proxy_hostname == NULL)
  {
    fprintf(stderr, "Please specify either \"--files [DIRECTORY]\" or \n"
                    "                      \"--proxy [HOSTNAME:PORT]\"\n");
    exit_with_usage();
  }

#ifdef POOLSERVER
  if (num_threads < 1)
  {
    fprintf(stderr, "Please specify \"--num-threads [N]\"\n");
    exit_with_usage();
  }
#endif

  chdir(server_files_directory);
  serve_forever(&server_fd, request_handler);

  return EXIT_SUCCESS;
}
