#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <semaphore.h>
#define ERR(source) \
    (fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), perror(source), kill(0, SIGKILL), exit(EXIT_FAILURE))
#define SEM_NAME "my_sem2"
#define SHM_NAME "my_shm2"

typedef struct 
{
    int intialised,counter,hits,samples;
    pthread_mutex_t mutex;
} shared_data_t;


void usage(char* name)
{
    fprintf(stderr, "USAGE: %s N\n", name);
    exit(EXIT_FAILURE);
}

void TryInitSharedData(shared_data_t* shared_data)
{
    if(shared_data->intialised != 1){
    shared_data->intialised = 1;
    shared_data->counter = 0;
    shared_data->hits = 0;
    shared_data->samples = 0;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&shared_data->mutex, &attr);
    }
}

void MutexLock(pthread_mutex_t* mutex)
{
    int error;
    if ((error = pthread_mutex_lock(mutex)) != 0)
    {
        if (error == EOWNERDEAD)
        {
            if ((error = pthread_mutex_consistent(mutex)) != 0)
                ERR("pthread_mutex_consistent");
        }
        else
            ERR("pthread_mutex_lock");
    }
}

void CleanUp()
{
    sem_unlink(SEM_NAME);
    shm_unlink(SHM_NAME);
}

int MonteCarlo(int N){
    int M = 0;
    for (int i = 0; i < N; i++)
    {
        double x = (double)rand() / RAND_MAX;
        double y = (double)rand() / RAND_MAX;
        if (x * x + y * y <= 1)
            M++;
    }
    return M;
}

void DoWork(int N, shared_data_t* shared_data)
{
    for(int i = 0; i < 3;i++){
    int result = MonteCarlo(N);
    MutexLock(&shared_data->mutex);
    shared_data->hits = shared_data->hits + result;
    shared_data->samples = shared_data->samples + N;
    fprintf(stderr, "Current Values: hits = %d, samples = %d\n", shared_data->hits, shared_data->samples);
    pthread_mutex_unlock(&shared_data->mutex);
    sleep(1);
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2)
        usage(argv[0]);
    
    int N = atoi(argv[1]);

    srand(getpid());

    sem_t* sem = sem_open(SEM_NAME, O_CREAT, 0666, 1);
    
    int shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT,0666);
    ftruncate(shm_fd, sizeof(shared_data_t));
    
    char* shm_ptr = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED)
        ERR("shm_open");
    
    shared_data_t* shared_data = (shared_data_t*)shm_ptr;

    //shared_data->intialised = 0;
    
    if (sem_trywait(sem) == 0)
    TryInitSharedData(shared_data);
    sem_post(sem);
    sem_close(sem);
    
    MutexLock(&shared_data->mutex);
    shared_data->counter = shared_data->counter + 1;
    pthread_mutex_unlock(&shared_data->mutex);
    
    DoWork(N, shared_data);
    
    MutexLock(&shared_data->mutex);
    shared_data->counter = shared_data->counter - 1;
    if (shared_data->counter == 0)
    {
        fprintf(stderr,"Final result: pi = %f\n", 4.0 * shared_data->hits / shared_data->samples);
        pthread_mutex_unlock(&shared_data->mutex);
        pthread_mutex_destroy(&shared_data->mutex);
        munmap(shm_ptr, sizeof(shared_data_t));
        CleanUp();
    }
    else
        pthread_mutex_unlock(&shared_data->mutex); 
    return EXIT_SUCCESS;
}