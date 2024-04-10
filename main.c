#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ERR(source)                                                            \
  (fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), perror(source),             \
   kill(0, SIGKILL), exit(EXIT_FAILURE))

typedef struct tagShared {
  pthread_mutex_t mutex;
  int counter;
} shared_t;

typedef struct tagChildData {
  shared_t *shared;
  sem_t *sem_m;
} child_data_t;

// void child_routine(child_data_t shared) {}

// void create_children(const int N, child_data_t shared) {
//   for (int i = 0; i < N; i++) {
//     switch (fork()) {
//     case 0:
//       child_routine(shared);
//       exit(EXIT_SUCCESS);
//     case -1:
//       ERR("fork");
//       break;
//     }
//   }
// }

int main(int argc, char **argv) {
  int fd;
  int N = atoi(argv[1]);
  child_data_t data;

  if (SEM_FAILED ==
      (data.sem_m = sem_open("/sem_m", O_CREAT | O_EXCL | O_RDWR, 0600, 1))) {
    if (errno == EEXIST) {
      if (SEM_FAILED == (data.sem_m = sem_open("/sem_m", O_RDWR)))
        ERR("shm_open shm");
    } else {
      ERR("sem_open");
    }
  }
  if (0 > sem_wait(data.sem_m))
    ERR("sem-wait");
  if (0 > (fd = shm_open("/shm", O_CREAT | O_EXCL | O_RDWR, 0600))) {
    if (errno == EEXIST) {
      if (0 > (fd = shm_open("/shm", O_RDWR, 0)))
        ERR("shm_open shm");
    } else {
      ERR("shm_open create");
    }
  }

  if (0 > ftruncate(fd, sizeof(shared_t)))
    ERR("ftrunc");
  shared_t *shared;
  if (MAP_FAILED == (data.shared = (shared_t *)mmap(NULL, sizeof(shared_t),
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_SHARED, fd, 0)))
    ERR("mmap");
  if (0 > close(fd))
    ERR("close");
  pthread_mutexattr_t m_attr;
  printf("[%d]Counter: [%d]\n", data.shared->counter, (int)getpid());
  if (data.shared->counter == 0) {
    puts("skljdhkjs");
    if (0 != pthread_mutexattr_init(&m_attr))
      ERR("muetx attr");
    if (0 != pthread_mutexattr_setpshared(&m_attr, PTHREAD_PROCESS_SHARED))
      ERR("muetx set pshared");
    if (0 != pthread_mutex_init(&data.shared->mutex, &m_attr))
      ERR("muetx set pshared");
  }

  if (0 > sem_post(data.sem_m))
    ERR("sem_post");

  // create_children(N, data);
  puts("Shjh");
  if (0 != pthread_mutex_lock(&data.shared->mutex))
    ERR("lock");
  data.shared->counter += 1;
  //printf("[%d]Counter: [%d]\n", data.shared->counter, (int)getpid());
  if (0 != pthread_mutex_unlock(&data.shared->mutex))
    ERR("unlock");
  // sleep(2);

  if (0 > sem_close(data.sem_m))
    ERR("sem_close");
  if (data.shared->counter == N) {
    printf("Counter: [%d]\n", data.shared->counter);
    if (0 != pthread_mutex_destroy(&data.shared->mutex))
      ERR("destroy muetx attr");
    if (0 > sem_unlink("/sem_m"))
      ERR("sem_unlink");
    if (0 > shm_unlink("/shm"))
      ERR("shm_unlink");
  }
  if (0 != pthread_mutexattr_destroy(&m_attr))
      ERR("destroy muetx attr");
  if (0 > munmap(data.shared, sizeof(shared_t)))
    ERR("munmap");
  return EXIT_SUCCESS;
}