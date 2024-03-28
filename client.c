#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NAMEBUF 100
#define INPUTBUFF 200
#define MSGSIZE 512
#define ERR(source)                                                            \
  (fprintf(stderr, "%s:%d\n", __FILE__, __LINE__), perror(source),             \
   kill(0, SIGKILL), exit(EXIT_FAILURE))

typedef struct {
  pid_t pid;
  char operands[INPUTBUFF];
} message_t;

void set_name(char *name, pid_t pid) {
  memset(name, 0, NAMEBUF);
  snprintf(name, NAMEBUF, "/%ld", (long)pid);
}

void close_mq(mqd_t mq) {
  if (0 > mq_close(mq))
    ERR("mq_close mq");
}

void destroy_mq(char *name) {
  if (0 > mq_unlink(name))
    ERR("mq_unlink mq");
}

void create_message_buf(message_t msg, char *msg_buf) {
  snprintf(msg_buf, MSGSIZE, "%ld %s", (long)msg.pid, msg.operands);
}

int main(int argc, char **argv) {

  message_t msg;
  mqd_t mq, mq_server;
  struct mq_attr attr;
  char name[NAMEBUF];
  char input[INPUTBUFF];
  char message_buff[MSGSIZE];
  char result_buff[MSGSIZE];

  struct timespec ts;

  if (argc != 2)
    printf("Indicate server mqueue\n");

  memset(&attr, 0, sizeof(struct mq_attr));
  memset(&msg, 0, sizeof(message_t));
  memset(input, 0, INPUTBUFF);
  memset(message_buff, 0, MSGSIZE);
  msg.pid = getpid();
  set_name(name, msg.pid);

  attr.mq_maxmsg = 10;
  attr.mq_msgsize = MSGSIZE;

  if ((mqd_t)-1 == (mq_server = mq_open(argv[1], O_WRONLY))) {
    // destroy_mq(name);
    ERR("mq_open mqs");
  }

  if ((mqd_t)-1 ==
      (mq = mq_open(name, O_CREAT | O_EXCL | O_RDONLY, 0600, &attr))) {
    // destroy_mq(name);
    ERR("mq_open mqs");
  }
  printf("%s\n", name);

  while (NULL != fgets(msg.operands, INPUTBUFF, stdin)) {

    msg.operands[strlen(msg.operands) - 1] = '\0';

    create_message_buf(msg, message_buff);

    if (-1 == mq_send(mq_server, message_buff, MSGSIZE, 0))
      ERR("mq_send to server");

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
      perror("clock_gettime");
      exit(EXIT_FAILURE);
    }

    ts.tv_nsec += 100 * 1000000; // 100ms in nanoseconds
    if (ts.tv_nsec >= 1000000000) {
      ts.tv_sec += 1;
      ts.tv_nsec -= 1000000000;
    }

    if (-1 == mq_timedreceive(mq, result_buff, MSGSIZE, NULL, &ts))
      ERR("mq_receive from server");

    printf("Result: %d\n", *((int *)result_buff));
  }

  close_mq(mq);
  close_mq(mq_server);
  destroy_mq(name);

  return EXIT_SUCCESS;
}