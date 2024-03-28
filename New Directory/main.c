#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAXBUF 100
#define MSGSIZE 512
#define RESSIZE 256

#define ERR(source)                                                            \
  (fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), perror(source),             \
   kill(0, SIGKILL), exit(EXIT_FAILURE))

volatile sig_atomic_t last_signal = 0;
typedef unsigned int UINT;
typedef struct timespec timespec_t;
typedef struct {
  pthread_mutex_t mtx;
  pthread_cond_t cv;
  int N;
} context_t;

#define SHM_SIZE sizeof(context_t)
// void sigint_handler(int sig, siginfo_t *info, void *p) { last_signal = sig; }

void sig_handler(int sig) { last_signal = sig; }

void sethandler(void (*f)(int, siginfo_t *, void *), int sigNo) {
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_sigaction = f;
  act.sa_flags = SA_SIGINFO;
  if (-1 == sigaction(sigNo, &act, NULL))
    ERR("sigaction");
}

void msleep(UINT milisec) {
  int ret = 0;
  time_t sec = (int)(milisec / 1000);
  milisec = milisec - (sec * 1000);
  timespec_t req = {0};
  req.tv_sec = sec;
  req.tv_nsec = milisec * 1000000L;
  if (-1 == nanosleep(&req, &req)) {
    if (errno == EINTR) {
      nanosleep(&req, NULL);
    } else {
      ERR("nanosleep");
    }
  }
}

void set_task_name(char *name, pid_t pid) {
  memset(name, 0, MAXBUF);
  snprintf(name, MAXBUF, "/task_queue_%ld", (long)pid);
}

void set_result_name(char *name, pid_t server_pid, pid_t pid_client) {
  memset(name, 0, MAXBUF);
  snprintf(name, MAXBUF, "/result_queue_%ld_%ld", (long)server_pid,
           (long)pid_client);
}

void worker_job(mqd_t mq_task, context_t *ctx) {
  srand(getpid());
  pid_t worker_id = getpid();
  mqd_t mq_worker_result;
  struct mq_attr worker_attr;
  worker_attr.mq_maxmsg = 10;
  worker_attr.mq_msgsize = RESSIZE;

  UINT delay = 0;
  double numbers[2] = {0.0, 0.0};
  double result = 0.0;
  int counter = 5;
  int msg_prio = 0;
  char task_buff[MSGSIZE];
  char *token;
  char result_buff[RESSIZE];
  memset(result_buff, 0, RESSIZE);
  memset(task_buff, 0, MSGSIZE);

  char name_result[RESSIZE];
  set_result_name(name_result, getppid(), worker_id);
  pthread_mutex_lock(&ctx->mtx);
  if (-1 == (mq_worker_result = mq_open(name_result, O_CREAT | O_EXCL | O_RDWR,
                                        0600, &worker_attr)))
    ERR("mq_open worker_queue");
  ctx->N--;
  pthread_cond_signal(&ctx->cv);
  pthread_mutex_unlock(&ctx->mtx);
  // kill(getppid(), SIGUSR1);

  printf("[%ld] Worker ready!\n", (long)worker_id);
  while (1) {
    //puts("Received");
    if (-1 == mq_receive(mq_task, task_buff, MSGSIZE, &msg_prio)) {
      if (errno == EAGAIN) {
        continue;
      }
      ERR("mq_receive from mqtask");
    }
    //puts("Received");

    if (msg_prio == 0){
      //puts("\nEXIT WORKER \t EXIT \n");
      break;
    }
    printf("[%ld] Received task [%lf, %lf]\n", (long)worker_id, numbers[0],
           numbers[1]);
    token = strtok(task_buff, " ");
    if (token != NULL) {
      numbers[0] = strtod(token, NULL);
      token = strtok(NULL, " ");
    }

    if (token != NULL)
      numbers[1] = strtod(token, NULL);

    delay = 500 + rand() % 1500;
    msleep(delay);

    result = numbers[0] + numbers[1];

    *((double *)result_buff) = result;

    printf("[%ld] Result sent: [%lf]\n", (long)worker_id, result);
    
    //puts("Send");
    if (-1 == mq_send(mq_worker_result, result_buff, RESSIZE, 0)) {
      ERR("mq_send mq_task");
    }
    //puts("Sent");
    // if (--counter == 0)
    // break;
  }
  if (mq_close(mq_worker_result) < 0)
    ERR("mq_close mq_task");
  // if (mq_unlink(name_result) < 0)
  //   ERR("mq_unlink task_name");
  printf("[%ld] Exits!\n", (long)worker_id);
}

pid_t *create_workers(const int N, mqd_t mq_task, context_t *ctx) {
  pid_t *client_ids = (pid_t *)calloc(N, sizeof(pid_t));
  for (int i = 0; i < N; i++) {
    switch ((client_ids[i] = fork())) {
    case 0:
      sethandler(SIG_IGN, SIGINT);
      worker_job(mq_task, ctx);
      if (mq_close(mq_task) < 0)
        ERR("mq_close mq_task");
      free(client_ids);
      exit(EXIT_SUCCESS);
      break;
    case -1:
      ERR("fork");
      break;
    }
  }
  return client_ids;
}

void parent_job(mqd_t mq_task, const int N, const UINT T1, const UINT T2,
                mqd_t *mq_clients, pid_t *client_ids) {
  srand(time(NULL));
  char task_buff[MSGSIZE];
  char result_buff[RESSIZE];
  struct mq_attr check_attr;
  for (int i = 0; i < N; i++) {
    memset(result_buff, 0, RESSIZE);
  }

  double numbers[2] = {0.0, 0.0};
  UINT delay;

  while (1) {
    for (int i = 0; i < 5 * N; i++) {
      delay = T1 + rand() % (T2 - T1);
      msleep(delay);
      numbers[0] = rand() % 100;
      numbers[1] = rand() % 100;
      mq_getattr(mq_task, &check_attr);
      printf("Number of msg: %ld\n", check_attr.mq_curmsgs);
      if(check_attr.mq_curmsgs == 5){
        puts("Queue is full");
      }
      //printf("[%lf %lf]\n", numbers[0], numbers[1]);
      memset(task_buff, 0, MSGSIZE);
      snprintf(task_buff, MSGSIZE, "%lf %lf", numbers[0], numbers[1]);
      //puts("Batya eceived");
      if (-1 == mq_send(mq_task, task_buff, MSGSIZE, 1)) {
        if (errno == EAGAIN) {
          puts("Queue is full");
        } else {
          ERR("mq_send mq_task");
        }
      }
      //puts("Batya eceived");
      printf("New task queued: [%lf, %lf]\n", numbers[0], numbers[1]);
    }

    puts("OUT LOOP");
    for (int i = 0; i < N; i++) {
      for (int j = 0; j < 5; j++) {
        puts("IN LOOP");
        if (-1 == TEMP_FAILURE_RETRY(mq_receive(mq_clients[i], result_buff, RESSIZE, NULL))) {
          ERR("mq_receive from mq clients[i]");
        }
        printf("Result from %ld: %lf\n", (long)client_ids[i],
               *((double *)result_buff));
      }
    }
    if (last_signal == SIGINT) {
      puts("TERMINATION OF THE SERVER");
      int n = N;
      char signal[MSGSIZE];
      memset(signal, 0, MSGSIZE);
      signal[0] = 'e';
      while (n) {
        //puts("Send signal start");
        if (-1 == mq_send(mq_task, signal, MSGSIZE, 0)) {
            ERR("mq_send mq_task");
          }
          --n;
        //puts("Send signal end");
          
        }
      last_signal = 0;
      break;
    }
  }
}
int main(int argc, char **argv) {


  pid_t server_id = getpid();
  char task_name[MAXBUF];
  if (argc != 4)
    puts("Indicate no of children");
  sethandler(sig_handler, SIGINT);
  mqd_t mq_task;
  int N = atoi(argv[1]);
  int T1 = atoi(argv[2]);
  int T2 = atoi(argv[3]);
  char client_result_name[N][MAXBUF];
  mqd_t mq_clients[N];
  pid_t *clients_ids = NULL;
  for (int i = 0; i < N; i++) {
    memset(client_result_name[i], 0, MAXBUF);
  }

  shm_unlink("/sop_shm");

  int fd = shm_open("/sop_shm", O_CREAT | O_EXCL | O_RDWR, 0600);

  if (fd < 0) {
    ERR("shm_open");
  }

  if (ftruncate(fd, SHM_SIZE) < 0) {
    ERR("ftruncate");
  }

  void *ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    ERR("mmap");
  }

  close(fd);

  context_t *ctx = (context_t *)ptr;
  memset(ctx, 0, sizeof(context_t));

  pthread_mutexattr_t mutex_attr;
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);

  pthread_condattr_t cond_attr;
  pthread_condattr_init(&cond_attr);
  pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);

  if (pthread_mutex_init(&ctx->mtx, &mutex_attr) != 0) {
    ERR("pthread_mutex_init");
  }
  if (pthread_cond_init(&ctx->cv, &cond_attr) != 0) {
    ERR("pthread_cond_init");
  }

  ctx->N = N;
  struct mq_attr task_attr;
  task_attr.mq_maxmsg = 5;
  task_attr.mq_msgsize = MSGSIZE;

  set_task_name(task_name, server_id);

  if (-1 ==
      (mq_task = mq_open(task_name, O_CREAT | O_EXCL | O_RDWR ,
                         0600, &task_attr)))
    ERR("mq_open task_queue");

  puts("Server is starting...\n");
  clients_ids = create_workers(N, mq_task, ctx);
  for (int i = 0; i < N; i++) {
    set_result_name(client_result_name[i], server_id, clients_ids[i]);
  }

  // sigset_t mask, oldmask;
  // sigemptyset(&mask);
  // sigaddset(&mask, SIGUSR1);
  // sigprocmask(SIG_BLOCK, &mask, &oldmask);

  pthread_mutex_lock(&ctx->mtx);
  while (ctx->N > 0) {
    pthread_cond_wait(&ctx->cv, &ctx->mtx);
  }

  for (int i = 0; i < N; i++) {
    if (-1 == (mq_clients[i] = mq_open(client_result_name[i], O_RDWR  )))
      ERR("mq_open client_result_queue[i]");
    printf("%ld\n", (long)mq_clients[i]);
  }
  pthread_mutex_unlock(&ctx->mtx);
  // sigprocmask(SIG_UNBLOCK, &mask, NULL);

  parent_job(mq_task, N, T1, T2, mq_clients, clients_ids);

  while (wait(NULL) < 0)
    ;
  msleep(2000);
  puts("All child processes have finished...");

  pthread_mutex_destroy(&ctx->mtx);
  pthread_cond_destroy(&ctx->cv);

  if (mq_close(mq_task) < 0)
    ERR("mq_close mq_task");
  if (mq_unlink(task_name) < 0)
    ERR("mq_unlink task_name");
  free(clients_ids);
  munmap(ptr, SHM_SIZE);
  return EXIT_SUCCESS;
}