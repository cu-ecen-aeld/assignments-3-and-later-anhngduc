/*
** server.c -- a stream socket server demo
*/
#define _GNU_SOURCE
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

#include "aesdsocket.h"

#define PORT "9000"      // the port users will be connecting to
#define MAXDATASIZE 1024 // max number of bytes we can get at once
#define BACKLOG 10       // how many pending connections queue will hold
#define FILE_PATH "/var/tmp/aesdsocketdata"

char terminate = 0;
pthread_mutex_t mutex; 
SLIST_HEAD(slisthead, slist_data_s) head;

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

void *threadfunc(void *thread_param)
{
    // printf("Start threadFunc\n" );
    struct thread_data *thread_func_args = (struct thread_data *)thread_param;
    bool success = true;
    // printf("wait_to_obtain_ms: %d\n", thread_func_args->wait_to_obtain_ms);
    
    int rc = pthread_mutex_lock(thread_func_args->mutex);
    if (rc != 0)
    {
        printf("pthread_mutex_lock failed with %d\n", rc);
        success = false;
    }
    else
    {
        // printf("wait_to_release_ms: %d\n", thread_func_args->wait_to_release_ms);
        
        
        printf("Job %lu start: socket: %d, new_fd: %d\n", thread_func_args->tid_value,\
             thread_func_args->sockfd, thread_func_args->new_fd); 
    
        int numbytes = 0;
        char buf[MAXDATASIZE];
        char *nl = "\n";

        FILE *fptr = NULL;

        // Open and write string to file
        fptr = fopen(FILE_PATH, "a+");

        while (((numbytes = recv(thread_func_args->new_fd, buf, MAXDATASIZE - 1, 0)) != -1))
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
            if (send(thread_func_args->new_fd, line, read, 0) == -1)
                perror("send");
        }
        if (line)
            free(line);

        // Close file, socket
        fclose(fptr);
        syslog(LOG_INFO, "Closed connection from %s\n", thread_func_args->s);
        close(thread_func_args->new_fd);
        printf("Closed connection from %s\n", thread_func_args->s);
        printf("Job %lu has finished\n", thread_func_args->tid_value); 
        
    }

    pthread_mutex_unlock(thread_func_args->mutex);
    if (rc != 0)
    {
        printf("pthread_mutex_unlock failed with %d\n", rc);
        success = false;
    }

    thread_func_args->thread_complete_success = success;
    return thread_param;
}

bool stop_thread = false;
pthread_t timer_tid;

void *thread_timer(void *thread_param)
{
    int count = 0;
    //bool success = true;
    while (!stop_thread)
    {
        sleep(1);
        count++;
        if (count == 9){
            count = 0;

            // write to file
            int rc = pthread_mutex_lock(&mutex);
            if (rc != 0)
            {
                printf("pthread_mutex_lock failed with %d\n", rc);
                //success = false;
            }
            else
            {
                char outstr[200];
                time_t t;
                struct tm *tmp;

                t = time(NULL);
                tmp = localtime(&t);
                if (tmp == NULL) {
                    perror("localtime");
                    exit(EXIT_FAILURE);
                }

                if (strftime(outstr, sizeof(outstr), "%a %b %d  %T %Y\n", tmp) == 0) {
                    fprintf(stderr, "strftime returned 0");
                    exit(EXIT_FAILURE);
                }
               
                FILE *fptr = NULL;

                // Open and write string to file
                fptr = fopen(FILE_PATH, "a+");
                fprintf(fptr, "timestamp: %s", outstr);
                

                // Close file, socket
                fclose(fptr);
                
            }

            pthread_mutex_unlock(&mutex);
            if (rc != 0)
            {
                printf("pthread_mutex_unlock failed with %d\n", rc);
                // success = false;
            }
        }
        
    }
    return thread_param;
}

void clean(int fd1){
    slist_data_t *datap=NULL;
    void *ret;

    // close socket
    close(fd1);
    fd1 = -1;

    // delete file
    remove(FILE_PATH);

    // clean linked-list
    while (!SLIST_EMPTY(&head)) {
        datap = SLIST_FIRST(&head);
        printf("[Clean] try tid: %lu: ", datap->tid_value);
        if (datap->params->thread_complete_success){
            printf("Finished -> join & free data\n"); // prints true
            if (pthread_join(datap->tid_value, &ret) != 0) {
                perror("pthread_join() error\n");
                // return -1;
            }
            SLIST_REMOVE_HEAD(&head, entries);
            if (datap->params != NULL) free(datap->params);
            free(datap);
        } else {
            printf("not finished yet -> next.\n");
        }
        
    }
    pthread_mutex_destroy(&mutex);
    stop_thread = true;
    if (pthread_join(timer_tid, &ret) != 0) {
        perror("pthread_join() error\n");
        // return -1;
    }
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

    pthread_t thid;
    void *ret;
    
    int list_size = 0;
    slist_data_t *datap=NULL, *np_temp=NULL;

    
    
    SLIST_INIT(&head);

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
    if (pthread_mutex_init(&mutex, NULL) != 0)
        {
            printf("\n mutex init has failed\n");
            return -1;
        }
    
    // create new thread
        if (pthread_create(&timer_tid, NULL, thread_timer, NULL) != 0) {
            perror("pthread_create(thread_timer) error");
            clean(sockfd);
            return success ? 0 : -1;
        }

    while (1)
    { // main accept() loop

        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        // printf("new_fd: %d\n", new_fd);
        if (new_fd == -1)
        {
            perror("accept error");
            if (caught_sigint || caught_sigterm)
            {
                printf("\nCaught SIGINT or SIGTERM in accept!\n");
                clean(sockfd);
                
                return success ? 0 : -1;
            }
            continue;
        }

        struct thread_data *params = malloc(sizeof(struct thread_data));
        memset(params, 0, sizeof(struct thread_data));
        params->new_fd = new_fd;
        params->sockfd = sockfd;

        params->mutex = &mutex;

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);
        printf("server: Accepted connection from %s\n", s);
        syslog(LOG_INFO, "Accepted connection from %s\n", s);

        // create new thread
        if (pthread_create(&thid, NULL, threadfunc, params) != 0) {
            perror("pthread_create() error");
            clean(sockfd);
            return success ? 0 : -1;
        }

        // allocate new node in link-list
        datap = malloc(sizeof(slist_data_t));
        memset(datap, 0, sizeof(slist_data_t));
        datap->tid_value = thid;
        params->tid_value = thid;
        strcpy(params->s, s);
        datap->params = params;
        list_size++;
        printf("Insert: %lu, count: %d\n", thid, list_size);
        
        SLIST_INSERT_HEAD(&head, datap, entries);

        printf("Loop through link-list.\n");
        // use _SAFE function to clean the data on the go
        SLIST_FOREACH_SAFE(datap, &head, entries,np_temp) {
            printf("TID: %lu: ", datap->tid_value);
            
            if (datap->params->thread_complete_success){
                printf("Finished -> join & remove from slist\n"); // prints true
                
                if (pthread_join(datap->tid_value, &ret) != 0) {
                    perror("pthread_join() foreach error \n");
                    return success ? 0 : -1;
                }
                
                SLIST_REMOVE(&head, datap, slist_data_s, entries);
                if (datap->params != NULL) free(datap->params);
                if (datap!= NULL) free(datap);
                

            } else {
                printf(" running. -> next\n");
            }
        }

        if (caught_sigint || caught_sigterm)
        {
            printf("\nCaught SIGINT or SIGTERM!\n");
            clean(sockfd);

            return success ? 0 : -1;
        }
    }

    return success ? 0 : -1;
}
