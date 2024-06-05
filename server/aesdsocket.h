#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include "queue.h" // queue taken from FreeBSD 10
#include <time.h>

// SLIST.
typedef struct slist_data_s slist_data_t;
struct slist_data_s {
    pthread_t tid_value;
    struct thread_data *params;
    SLIST_ENTRY(slist_data_s) entries;
};


struct thread_data{
    
    int new_fd, sockfd;
    pthread_t tid_value;
    char s[INET6_ADDRSTRLEN];
    /**
    * The mutex used to lock this account when manipulating values, for thread safety
    */ 
    pthread_mutex_t *mutex;
    bool thread_complete_success;
};