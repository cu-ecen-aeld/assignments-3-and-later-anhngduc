/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>

#define PORT "9000"      // the port users will be connecting to
#define MAXDATASIZE 1024 // max number of bytes we can get at once
#define BACKLOG 10       // how many pending connections queue will hold
#define FILE_PATH "/var/tmp/aesdsocketdata"

char terminate = 0;

void sigchld_handler(int s)
{
    (void)s; // quiet unused variable warning

    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

bool caught_sigint = false;
bool caught_sigterm = false;

static void signal_handler(int signal_number)
{
    /**
     * Save a copy of errno so we can restore it later.  See https://pubs.opengroup.org/onlinepubs/9699919799/
     * "Operations which obtain the value of errno and operations which assign a value to errno shall be
     *  async-signal-safe, provided that the signal-catching function saves the value of errno upon entry and
     *  restores it before it returns."
     */
    int errno_saved = errno;
    if (signal_number == SIGINT)
    {
        caught_sigint = true;
    }
    else if (signal_number == SIGTERM)
    {
        caught_sigterm = true;
    }
    errno = errno_saved;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    openlog(NULL, 0, LOG_USER);
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    bool success = true;
    bool daemon_mode = false;

    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        printf("RUN IN DAEMON mode!!\n");
        syslog(LOG_INFO, "RUN IN DAEMON mode!!");
        daemon_mode = true;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            return -1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
    pid_t child_pid = 0;
    if (daemon_mode){
        printf("FORK?\n");
        child_pid = fork();
        if (child_pid == -1)
            return -1;
        else if (child_pid == 0){
            printf("Child process\n");
        } else {
            printf("Parent process\nThe process ID of child is %d.\n", child_pid);
            exit(0);
        }
    }

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        return -1;
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        return -1;
    }

    // sigterm_handler
    struct sigaction new_action;
    
    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler = signal_handler;
    if (sigaction(SIGTERM, &new_action, NULL) != 0)
    {
        printf("Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        success = false;
    }
    if (sigaction(SIGINT, &new_action, NULL))
    {
        printf("Error %d (%s) registering for SIGINT", errno, strerror(errno));
        success = false;
    }

    printf("Listening.\nWaiting for connection request.\n");

    while (1)
    { // main accept() loop

        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept error");
            if (caught_sigint || caught_sigterm)
            {
                printf("\nCaught SIGINT or SIGTERM in accept!\n");
                if (sockfd) close(sockfd);
                if (new_fd) close(new_fd);
                remove(FILE_PATH);
                
                return success ? 0 : 1;
            }
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: Accepted connection from %s\n", s);
        syslog(LOG_INFO, "Accepted connection from %s\n", s);

        if (!fork())
        {                  // this is the child process
            close(sockfd); // child doesn't need the listener
                           // if (send(new_fd, "Hello, world!", 13, 0) == -1)
                           // 	perror("send");
            int numbytes = 0;
            char buf[MAXDATASIZE];
            char *nl = "\n";

            FILE *fptr;
            syslog(LOG_DEBUG, "Writing %s to %s", buf, FILE_PATH);

            // Open and write string to file
            fptr = fopen(FILE_PATH, "a+");

            while (((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) != -1))
            {
                buf[numbytes] = '\0';
                printf("server: received '%s'\n", buf);
                fprintf(fptr, "%s", buf);
                if (strpbrk(buf, nl) != NULL)
                    break;
            }

            fseek(fptr, 0, SEEK_SET);

            char *line = NULL;
            size_t len = 0;
            ssize_t read;

            while ((read = getline(&line, &len, fptr)) != -1)
            {
                printf("Retrieved line of length %zu:\n", read);
                printf("%s", line);
                if (send(new_fd, line, read, 0) == -1)
                    perror("send");
            }
            if (line)
                free(line);

            // Close file, socket
            fclose(fptr);
            syslog(LOG_INFO, "Closed connection from %s\n", s);
            close(new_fd);
            exit(0);
        }
        if (caught_sigint || caught_sigterm)
        {
            printf("\nCaught SIGINT or SIGTERM!\n");
            close(sockfd);
            remove(FILE_PATH);
            
            return success ? 0 : 1;
        }

        close(new_fd); // parent doesn't need this
    }

    return success ? 0 : -1;
}
