#include <errno.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXBUF 100
#define INPUTBUFF 200
#define MAXOPEN 3
#define MAXNAMES 3
#define MSGSIZE 512

#define ERR(source)                                                            \
  (fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), perror(source),             \
   kill(0, SIGKILL), exit(EXIT_FAILURE))

volatile sig_atomic_t last_signal = 0;

typedef struct {
  char names[MAXNAMES][MAXBUF];
  int mqds[MAXOPEN];
  struct mq_attr attr[MAXOPEN];
} mqueue_t;

typedef struct {
  pid_t pid;
  int operands[2];
  char result[MAXBUF];
} message_t;

void sigint_handler(int sig, siginfo_t *info, void *p) { last_signal = sig; }
void mq_handler(int sig, siginfo_t *info, void *p) {
  mqd_t *mq = (mqd_t *)info->si_value.sival_ptr;
  struct sigevent not ;
  not .sigev_notify = SIGEV_SIGNAL;
  not .sigev_signo = SIGRTMIN;
  not .sigev_value.sival_ptr = mq;
  if (mq_notify(*mq, &not ) < 0)
    ERR("mq_notify");
  last_signal = sig;
}

void sethandler(void (*f)(int, siginfo_t *, void *), int sigNo) {
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_sigaction = f;
  act.sa_flags = SA_SIGINFO;
  if (-1 == sigaction(sigNo, &act, NULL))
    ERR("sigaction");
}

void set_cname(char *name, pid_t pid) {
  memset(name, 0, MAXBUF);
  snprintf(name, MAXBUF, "/%ld", (long)pid);
}

void set_name(char *name, pid_t pid, char c) {
  memset(name, 0, MAXBUF);
  snprintf(name, MAXBUF, "/%ld_%c", (long)pid, c);
}

void print_names(mqueue_t mq_names) {
  for (size_t i = 0; i < MAXNAMES; i++)
    printf("%s\n", mq_names.names[i]);
}

int modulo(int *ops) { return ops[0] % ops[1]; }
int sum(int *ops) { return ops[0] + ops[1]; }
int division(int *ops) { return ops[0] / ops[1]; }

void create_mqs(mqueue_t *mq) {
  for (size_t i = 0; i < MAXOPEN; i++) {
    mq->attr[i].mq_maxmsg = 10;
    mq->attr[i].mq_msgsize = MSGSIZE;
    if ((mqd_t)-1 ==
        (mq->mqds[i] =
             mq_open(mq->names[i], O_CREAT | O_EXCL | O_RDONLY | O_NONBLOCK,
                     0600, &mq->attr[i]))) {
      ERR("mq_open mqs");
    }
  }
}

mqd_t get_message(message_t *msg, mqd_t mq) {
  char message_buff[MSGSIZE];
  if ((-1 == mq_receive(mq, message_buff, MSGSIZE, NULL))) {
    if (errno == EAGAIN)
      return (mqd_t)-2;
    ERR("mq_receive from client");
  }
  char *token = strtok(message_buff, " ");
  if (token != NULL) {
    msg->pid = atoi(token); // Convert first token to integer
    token = strtok(NULL, " ");
  }
  if (token != NULL) {
    msg->operands[0] = atoi(token); // Convert second token to integer
    token = strtok(NULL, " ");
  }
  if (token != NULL) {
    msg->operands[1] = atoi(token); // Convert third token to integer
  }

  return mq;
}

void send_result(mqd_t mq_client, message_t msg) {
  if (-1 == mq_send(mq_client, msg.result, MSGSIZE, 0))
    ERR("mq_receive to client");
}

void close_mq(mqueue_t mq) {
  for (size_t i = 0; i < MAXOPEN; i++) {
    if (0 > mq_close(mq.mqds[i]))
      ERR("mq_close mq");
  }
}

void destroy_mq(mqueue_t mq) {
  for (size_t i = 0; i < MAXOPEN; i++) {
    if (0 > mq_unlink(mq.names[i]))
      ERR("mq_close mq");
  }
}

int main(/*int argc, char** argv*/) {

  pid_t server_id = getpid();

  mqd_t mq_ready;
  mqd_t mq_client;
  mqueue_t mq;
  message_t msg;
  char client_name[MAXBUF];

  sethandler(sigint_handler, SIGUSR1);
  sethandler(mq_handler, SIGRTMIN);

  sigset_t mask, oldmask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGRTMIN);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, &oldmask);

  memset(&mq, 0, sizeof(mqueue_t));
  memset(&msg, 0, sizeof(message_t));

  set_name(mq.names[0], server_id, 's');
  set_name(mq.names[1], server_id, 'd');
  set_name(mq.names[2], server_id, 'm');

  create_mqs(&mq);
  print_names(mq);

  static struct sigevent noti[MAXOPEN];

  for (int i = 0; i < MAXOPEN; i++) {
    noti[i].sigev_notify = SIGEV_SIGNAL;
    noti[i].sigev_signo = SIGRTMIN;
    noti[i].sigev_value.sival_ptr = &mq.mqds[i];
    if (mq_notify(mq.mqds[i], &noti[i]) < 0)
      ERR("mq_notify");
  }

  puts("Server started\n");

  while (sigsuspend(&oldmask)) {
    if (last_signal == SIGRTMIN) {
      for (int i = 0; i < MAXOPEN; i++) {
        mq_ready = get_message(&msg, mq.mqds[i]);

        if (mq_ready == -2)
          continue;

        set_cname(client_name, msg.pid);

        printf("Client name: %s\n", client_name);

        if ((mqd_t)-1 == (mq_client = mq_open(client_name, O_WRONLY)))
          ERR("mq_open client");

        if (mq_ready == mq.mqds[0]) {
          *((int *)msg.result) = sum(msg.operands);
        }
        if (mq_ready == mq.mqds[1]) {
          *((int *)msg.result) = division(msg.operands);
        }
        if (mq_ready == mq.mqds[2]) {
          *((int *)msg.result) = modulo(msg.operands);
        }
        send_result(mq_client, msg);
        if (mq_close(mq_client) < 0)
          ERR("mq_client close");
      }
    }

    if (last_signal == SIGINT)
      break;
  }

  sigprocmask(SIG_UNBLOCK, &mask, NULL);

  close_mq(mq);
  destroy_mq(mq);

  puts("Server terminated\n");

  return EXIT_SUCCESS;
}et(task_buff, 0, MSGSIZE);
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