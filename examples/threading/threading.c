#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg, ...)
// #define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg, ...) printf("threading ERROR: " msg "\n", ##__VA_ARGS__)

void *threadfunc(void *thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    // struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    // printf("Start threadFunc\n" );
    struct thread_data *thread_func_args = (struct thread_data *)thread_param;
    bool success = true;
    // printf("wait_to_obtain_ms: %d\n", thread_func_args->wait_to_obtain_ms);
    usleep(thread_func_args->wait_to_obtain_ms * 1000);
    int rc = pthread_mutex_lock(thread_func_args->mutex);
    if (rc != 0)
    {
        printf("pthread_mutex_lock failed with %d\n", rc);
        success = false;
    }
    else
    {
        // printf("wait_to_release_ms: %d\n", thread_func_args->wait_to_release_ms);
        usleep(thread_func_args->wait_to_release_ms * 1000);
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

bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex, int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    int rc = 0;
    bool success = true;

    struct thread_data *params = malloc(sizeof(struct thread_data));
    memset(params, 0, sizeof(struct thread_data));
    params->wait_to_obtain_ms = wait_to_obtain_ms;
    params->wait_to_release_ms = wait_to_release_ms;
    // if (pthread_mutex_init(mutex, NULL) != 0)
    // {
    //     printf("\n mutex init has failed\n");
    //     return 1;
    // }
    params->mutex = mutex;

    rc = pthread_create(thread, NULL, threadfunc, params);
    if (rc != 0)
    {
        printf("pthread_create failed with error %d creating thread %ln\n", rc, thread);
        success = false;
    }
    return success;
}
