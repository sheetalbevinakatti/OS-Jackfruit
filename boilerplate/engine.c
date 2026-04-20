/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Task 1: multi-container runtime, namespaces, chroot, /proc, SIGCHLD reaping
 * Task 2: full CLI (start/run/ps/logs/stop), UNIX socket IPC, signal handling,
 *         run blocks until container exits, Ctrl+C forwards stop to supervisor
 * Task 3: bounded-buffer logging, producer/consumer threads
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE          (1024 * 1024)
#define CONTAINER_ID_LEN    32
#define CONTROL_PATH        "/tmp/mini_runtime.sock"
#define LOG_DIR             "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN   256
#define LOG_CHUNK_SIZE      4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT  (40UL << 20)
#define DEFAULT_HARD_LIMIT  (64UL << 20)

typedef enum { CMD_SUPERVISOR=0, CMD_START, CMD_RUN, CMD_PS, CMD_LOGS, CMD_STOP } command_kind_t;
typedef enum { CONTAINER_STARTING=0, CONTAINER_RUNNING, CONTAINER_STOPPED, CONTAINER_KILLED, CONTAINER_EXITED } container_state_t;

typedef struct container_record {
    char              id[CONTAINER_ID_LEN];
    pid_t             host_pid;
    time_t            started_at;
    container_state_t state;
    unsigned long     soft_limit_bytes;
    unsigned long     hard_limit_bytes;
    int               exit_code;
    int               exit_signal;
    int               stop_requested;
    char              log_path[PATH_MAX];
    int               log_pipe_read;
    int               run_client_fd;
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head, tail, count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty, not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes, hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status, exit_code, exit_signal;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value, log_write_fd;
} child_config_t;

typedef struct {
    int              server_fd, monitor_fd;
    volatile int     should_stop;
    pthread_t        logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t  metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static supervisor_ctx_t     *g_ctx = NULL;
static volatile sig_atomic_t g_run_got_signal = 0;
static char g_run_container_id[CONTAINER_ID_LEN] = {0};

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s supervisor <base-rootfs>\n"
        "  %s start <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s run   <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s ps\n  %s logs <id>\n  %s stop <id>\n",
        prog,prog,prog,prog,prog,prog);
}

static const char *state_to_string(container_state_t s) {
    switch(s){
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

static int parse_mib_flag(const char *flag, const char *value, unsigned long *target) {
    char *end=NULL; unsigned long mib; errno=0;
    mib = strtoul(value,&end,10);
    if(errno||end==value||*end){fprintf(stderr,"Invalid value for %s: %s\n",flag,value);return -1;}
    if(mib>ULONG_MAX/(1UL<<20)){fprintf(stderr,"Value for %s too large\n",flag);return -1;}
    *target=mib*(1UL<<20); return 0;
}

static int parse_optional_flags(control_request_t *req, int argc, char *argv[], int start) {
    int i;
    for(i=start;i<argc;i+=2){
        char *end=NULL; long nv;
        if(i+1>=argc){fprintf(stderr,"Missing value for %s\n",argv[i]);return -1;}
        if(!strcmp(argv[i],"--soft-mib")){if(parse_mib_flag("--soft-mib",argv[i+1],&req->soft_limit_bytes))return -1;continue;}
        if(!strcmp(argv[i],"--hard-mib")){if(parse_mib_flag("--hard-mib",argv[i+1],&req->hard_limit_bytes))return -1;continue;}
        if(!strcmp(argv[i],"--nice")){
            errno=0; nv=strtol(argv[i+1],&end,10);
            if(errno||end==argv[i+1]||*end||nv<-20||nv>19){fprintf(stderr,"Invalid --nice: %s\n",argv[i+1]);return -1;}
            req->nice_value=(int)nv; continue;
        }
        fprintf(stderr,"Unknown option: %s\n",argv[i]); return -1;
    }
    if(req->soft_limit_bytes>req->hard_limit_bytes){fprintf(stderr,"soft limit cannot exceed hard limit\n");return -1;}
    return 0;
}

/* ---------- Bounded buffer ---------- */
static int bounded_buffer_init(bounded_buffer_t *b) {
    int rc; memset(b,0,sizeof(*b));
    rc=pthread_mutex_init(&b->mutex,NULL); if(rc)return rc;
    rc=pthread_cond_init(&b->not_empty,NULL); if(rc){pthread_mutex_destroy(&b->mutex);return rc;}
    rc=pthread_cond_init(&b->not_full,NULL);
    if(rc){pthread_cond_destroy(&b->not_empty);pthread_mutex_destroy(&b->mutex);return rc;}
    return 0;
}
static void bounded_buffer_destroy(bounded_buffer_t *b) {
    pthread_cond_destroy(&b->not_full);pthread_cond_destroy(&b->not_empty);pthread_mutex_destroy(&b->mutex);
}
static void bounded_buffer_begin_shutdown(bounded_buffer_t *b) {
    pthread_mutex_lock(&b->mutex);b->shutting_down=1;
    pthread_cond_broadcast(&b->not_empty);pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}
int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item) {
    pthread_mutex_lock(&b->mutex);
    while(b->count==LOG_BUFFER_CAPACITY&&!b->shutting_down) pthread_cond_wait(&b->not_full,&b->mutex);
    if(b->shutting_down){pthread_mutex_unlock(&b->mutex);return -1;}
    b->items[b->tail]=*item; b->tail=(b->tail+1)%LOG_BUFFER_CAPACITY; b->count++;
    pthread_cond_signal(&b->not_empty); pthread_mutex_unlock(&b->mutex); return 0;
}
int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item) {
    pthread_mutex_lock(&b->mutex);
    while(b->count==0&&!b->shutting_down) pthread_cond_wait(&b->not_empty,&b->mutex);
    if(b->count==0){pthread_mutex_unlock(&b->mutex);return 0;}
    *item=b->items[b->head]; b->head=(b->head+1)%LOG_BUFFER_CAPACITY; b->count--;
    pthread_cond_signal(&b->not_full); pthread_mutex_unlock(&b->mutex); return 1;
}

/* ---------- Logging consumer thread ---------- */
void *logging_thread(void *arg) {
    supervisor_ctx_t *ctx=(supervisor_ctx_t*)arg; log_item_t item;
    while(1){
        if(!bounded_buffer_pop(&ctx->log_buffer,&item))break;
        char log_path[PATH_MAX]={0};
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c=ctx->containers;
        while(c){if(!strncmp(c->id,item.container_id,CONTAINER_ID_LEN)){strncpy(log_path,c->log_path,PATH_MAX-1);break;}c=c->next;}
        pthread_mutex_unlock(&ctx->metadata_lock);
        if(!log_path[0])continue;
        int fd=open(log_path,O_WRONLY|O_CREAT|O_APPEND,0644);
        if(fd<0)continue;
        (void)write(fd,item.data,item.length); close(fd);
    }
    return NULL;
}

/* ---------- Producer thread ---------- */
typedef struct { supervisor_ctx_t *ctx; int pipe_fd; char container_id[CONTAINER_ID_LEN]; } producer_arg_t;
static void *producer_thread(void *arg) {
    producer_arg_t *pa=(producer_arg_t*)arg; log_item_t item; ssize_t n;
    strncpy(item.container_id,pa->container_id,CONTAINER_ID_LEN-1);
    while((n=read(pa->pipe_fd,item.data,LOG_CHUNK_SIZE))>0){item.length=(size_t)n;bounded_buffer_push(&pa->ctx->log_buffer,&item);}
    close(pa->pipe_fd); free(pa); return NULL;
}

/* ---------- Kernel monitor helpers ---------- */
int register_with_monitor(int fd,const char *id,pid_t pid,unsigned long soft,unsigned long hard){
    struct monitor_request req; if(fd<0)return 0;
    memset(&req,0,sizeof(req)); req.pid=pid; req.soft_limit_bytes=soft; req.hard_limit_bytes=hard;
    strncpy(req.container_id,id,sizeof(req.container_id)-1);
    if(ioctl(fd,MONITOR_REGISTER,&req)<0){perror("ioctl MONITOR_REGISTER (non-fatal)");return -1;}
    return 0;
}
int unregister_from_monitor(int fd,const char *id,pid_t pid){
    struct monitor_request req; if(fd<0)return 0;
    memset(&req,0,sizeof(req)); req.pid=pid; strncpy(req.container_id,id,sizeof(req.container_id)-1);
    if(ioctl(fd,MONITOR_UNREGISTER,&req)<0)return -1; return 0;
}

/* ---------- Metadata helpers ---------- */
static container_record_t *find_container(supervisor_ctx_t *ctx,const char *id){
    container_record_t *c=ctx->containers;
    while(c){if(!strncmp(c->id,id,CONTAINER_ID_LEN))return c;c=c->next;}return NULL;
}
static void add_container(supervisor_ctx_t *ctx,container_record_t *rec){rec->next=ctx->containers;ctx->containers=rec;}

/* ---------- Task 1: child_fn ---------- */
int child_fn(void *arg){
    child_config_t *cfg=(child_config_t*)arg;
    if(sethostname(cfg->id,strlen(cfg->id))!=0) perror("sethostname (non-fatal)");
    if(chroot(cfg->rootfs)!=0){perror("chroot");return 1;}
    if(chdir("/")!=0){perror("chdir /");return 1;}
    mkdir("/proc",0555);
    if(mount("proc","/proc","proc",MS_NOEXEC|MS_NOSUID|MS_NODEV,NULL)!=0) perror("mount /proc (non-fatal)");
    if(cfg->nice_value!=0) if(nice(cfg->nice_value)==-1&&errno!=0) perror("nice (non-fatal)");
    if(cfg->log_write_fd>=0){
        if(dup2(cfg->log_write_fd,STDOUT_FILENO)<0||dup2(cfg->log_write_fd,STDERR_FILENO)<0){perror("dup2");return 1;}
        close(cfg->log_write_fd);
    }
    char *argv_exec[]={cfg->command,NULL};
    execv(cfg->command,argv_exec); perror("execv"); return 1;
}

/* ---------- Task 2: SIGCHLD handler ---------- */
static void sigchld_handler(int sig){
    (void)sig; int wstatus; pid_t pid;
    while((pid=waitpid(-1,&wstatus,WNOHANG))>0){
        if(!g_ctx)continue;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        container_record_t *c=g_ctx->containers;
        while(c){
            if(c->host_pid==pid){
                if(WIFEXITED(wstatus)){c->exit_code=WEXITSTATUS(wstatus);c->state=CONTAINER_EXITED;}
                else if(WIFSIGNALED(wstatus)){
                    c->exit_signal=WTERMSIG(wstatus);
                    c->state=c->stop_requested?CONTAINER_STOPPED:CONTAINER_KILLED;
                }
                if(c->run_client_fd>=0){
                    control_response_t final; memset(&final,0,sizeof(final));
                    final.status=0; final.exit_code=c->exit_code; final.exit_signal=c->exit_signal;
                    snprintf(final.message,CONTROL_MESSAGE_LEN,
                        "container '%s' exited state=%s code=%d sig=%d",
                        c->id,state_to_string(c->state),c->exit_code,c->exit_signal);
                    (void)write(c->run_client_fd,&final,sizeof(final));
                    close(c->run_client_fd); c->run_client_fd=-1;
                }
                unregister_from_monitor(g_ctx->monitor_fd,c->id,c->host_pid);
                break;
            }
            c=c->next;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig){(void)sig;if(g_ctx)g_ctx->should_stop=1;}

/* ---------- launch_container ---------- */
static int launch_container(supervisor_ctx_t *ctx,const control_request_t *req,control_response_t *resp,int run_client_fd){
    mkdir(LOG_DIR,0755);
    pthread_mutex_lock(&ctx->metadata_lock);
    if(find_container(ctx,req->container_id)){
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status=-1; snprintf(resp->message,CONTROL_MESSAGE_LEN,"container '%s' already exists",req->container_id); return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
    int pipefd[2];
    if(pipe(pipefd)!=0){perror("pipe");resp->status=-1;snprintf(resp->message,CONTROL_MESSAGE_LEN,"pipe() failed: %s",strerror(errno));return -1;}
    child_config_t *cfg=calloc(1,sizeof(*cfg));
    if(!cfg){close(pipefd[0]);close(pipefd[1]);resp->status=-1;snprintf(resp->message,CONTROL_MESSAGE_LEN,"calloc failed");return -1;}
    strncpy(cfg->id,req->container_id,CONTAINER_ID_LEN-1);
    strncpy(cfg->rootfs,req->rootfs,PATH_MAX-1);
    strncpy(cfg->command,req->command,CHILD_COMMAND_LEN-1);
    cfg->nice_value=req->nice_value; cfg->log_write_fd=pipefd[1];
    char *stack=malloc(STACK_SIZE);
    if(!stack){free(cfg);close(pipefd[0]);close(pipefd[1]);resp->status=-1;snprintf(resp->message,CONTROL_MESSAGE_LEN,"malloc stack failed");return -1;}
    pid_t pid=clone(child_fn,stack+STACK_SIZE,CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNS|SIGCHLD,cfg);
    free(stack); close(pipefd[1]);
    if(pid<0){perror("clone");free(cfg);close(pipefd[0]);resp->status=-1;snprintf(resp->message,CONTROL_MESSAGE_LEN,"clone() failed: %s",strerror(errno));return -1;}
    free(cfg);
    container_record_t *rec=calloc(1,sizeof(*rec));
    if(!rec){kill(pid,SIGKILL);close(pipefd[0]);resp->status=-1;snprintf(resp->message,CONTROL_MESSAGE_LEN,"calloc record failed");return -1;}
    strncpy(rec->id,req->container_id,CONTAINER_ID_LEN-1);
    rec->host_pid=pid; rec->started_at=time(NULL); rec->state=CONTAINER_RUNNING;
    rec->soft_limit_bytes=req->soft_limit_bytes; rec->hard_limit_bytes=req->hard_limit_bytes;
    rec->exit_code=0; rec->exit_signal=0; rec->stop_requested=0;
    rec->log_pipe_read=-1; rec->run_client_fd=run_client_fd;
    snprintf(rec->log_path,PATH_MAX,"%s/%s.log",LOG_DIR,req->container_id);
    register_with_monitor(ctx->monitor_fd,rec->id,pid,rec->soft_limit_bytes,rec->hard_limit_bytes);
    producer_arg_t *pa=calloc(1,sizeof(*pa));
    if(pa){
        pa->ctx=ctx; pa->pipe_fd=pipefd[0]; strncpy(pa->container_id,req->container_id,CONTAINER_ID_LEN-1);
        pthread_t tid;
        if(pthread_create(&tid,NULL,producer_thread,pa)==0) pthread_detach(tid);
        else{free(pa);close(pipefd[0]);}
    }else close(pipefd[0]);
    pthread_mutex_lock(&ctx->metadata_lock); add_container(ctx,rec); pthread_mutex_unlock(&ctx->metadata_lock);
    resp->status=0; snprintf(resp->message,CONTROL_MESSAGE_LEN,"started container '%s' pid=%d",req->container_id,pid);
    fprintf(stdout,"[supervisor] %s\n",resp->message); fflush(stdout);
    return 0;
}

/* ---------- handle_request ---------- */
static void handle_request(supervisor_ctx_t *ctx,int client_fd,const control_request_t *req){
    control_response_t resp; memset(&resp,0,sizeof(resp));
    switch(req->kind){
    case CMD_START:
        launch_container(ctx,req,&resp,-1);
        (void)write(client_fd,&resp,sizeof(resp));
        break;
    case CMD_RUN:{
        int run_fd=dup(client_fd);
        if(run_fd<0){resp.status=-1;snprintf(resp.message,CONTROL_MESSAGE_LEN,"dup failed");(void)write(client_fd,&resp,sizeof(resp));break;}
        int rc=launch_container(ctx,req,&resp,run_fd);
        if(rc!=0){(void)write(client_fd,&resp,sizeof(resp));close(run_fd);}
        else (void)write(client_fd,&resp,sizeof(resp));
        break;
    }
    case CMD_PS:{
        char buf[4096]={0}; int off=0;
        off+=snprintf(buf+off,sizeof(buf)-off,"%-16s %-8s %-10s %-10s %-10s %-10s\n","ID","PID","STATE","STARTED","SOFT-MiB","HARD-MiB");
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c=ctx->containers;
        while(c&&off<(int)sizeof(buf)-80){
            char tstr[32]; struct tm *tm=localtime(&c->started_at); strftime(tstr,sizeof(tstr),"%H:%M:%S",tm);
            off+=snprintf(buf+off,sizeof(buf)-off,"%-16s %-8d %-10s %-10s %-10lu %-10lu\n",
                c->id,c->host_pid,state_to_string(c->state),tstr,c->soft_limit_bytes>>20,c->hard_limit_bytes>>20);
            c=c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status=0; strncpy(resp.message,buf,CONTROL_MESSAGE_LEN-1);
        (void)write(client_fd,&resp,sizeof(resp));
        break;
    }
    case CMD_LOGS:{
        char log_path[PATH_MAX]={0};
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c=find_container(ctx,req->container_id);
        if(c)strncpy(log_path,c->log_path,PATH_MAX-1);
        pthread_mutex_unlock(&ctx->metadata_lock);
        if(!log_path[0]){resp.status=-1;snprintf(resp.message,CONTROL_MESSAGE_LEN,"container '%s' not found",req->container_id);(void)write(client_fd,&resp,sizeof(resp));break;}
        int fd=open(log_path,O_RDONLY);
        if(fd<0){resp.status=-1;snprintf(resp.message,CONTROL_MESSAGE_LEN,"log not found: %s",log_path);(void)write(client_fd,&resp,sizeof(resp));break;}
        resp.status=0; strncpy(resp.message,"OK",CONTROL_MESSAGE_LEN-1); (void)write(client_fd,&resp,sizeof(resp));
        char chunk[1024]; ssize_t n;
        while((n=read(fd,chunk,sizeof(chunk)))>0)(void)write(client_fd,chunk,(size_t)n);
        close(fd); return;
    }
    case CMD_STOP:{
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c=find_container(ctx,req->container_id);
        if(!c){pthread_mutex_unlock(&ctx->metadata_lock);resp.status=-1;snprintf(resp.message,CONTROL_MESSAGE_LEN,"container '%s' not found",req->container_id);(void)write(client_fd,&resp,sizeof(resp));break;}
        c->stop_requested=1; pid_t pid=c->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);
        if(kill(pid,SIGTERM)!=0&&errno==ESRCH){
            pthread_mutex_lock(&ctx->metadata_lock);
            c=find_container(ctx,req->container_id); if(c)c->state=CONTAINER_STOPPED;
            pthread_mutex_unlock(&ctx->metadata_lock);
        }
        resp.status=0; snprintf(resp.message,CONTROL_MESSAGE_LEN,"sent SIGTERM to container '%s' pid=%d",req->container_id,pid);
        (void)write(client_fd,&resp,sizeof(resp));
        break;
    }
    default:
        resp.status=-1; snprintf(resp.message,CONTROL_MESSAGE_LEN,"unknown command");
        (void)write(client_fd,&resp,sizeof(resp));
    }
}

/* ---------- run_supervisor ---------- */
static int run_supervisor(const char *rootfs){
    supervisor_ctx_t ctx; int rc;
    memset(&ctx,0,sizeof(ctx)); ctx.server_fd=-1; ctx.monitor_fd=-1; g_ctx=&ctx;
    rc=pthread_mutex_init(&ctx.metadata_lock,NULL); if(rc){errno=rc;perror("pthread_mutex_init");return 1;}
    rc=bounded_buffer_init(&ctx.log_buffer);
    if(rc){errno=rc;perror("bounded_buffer_init");pthread_mutex_destroy(&ctx.metadata_lock);return 1;}
    ctx.monitor_fd=open("/dev/container_monitor",O_RDWR);
    if(ctx.monitor_fd<0) fprintf(stderr,"[supervisor] kernel monitor not available (load monitor.ko for memory limits)\n");
    mkdir(LOG_DIR,0755);
    rc=pthread_create(&ctx.logger_thread,NULL,logging_thread,&ctx);
    if(rc){errno=rc;perror("pthread_create logger");bounded_buffer_destroy(&ctx.log_buffer);pthread_mutex_destroy(&ctx.metadata_lock);if(ctx.monitor_fd>=0)close(ctx.monitor_fd);return 1;}
    struct sigaction sa; memset(&sa,0,sizeof(sa)); sigemptyset(&sa.sa_mask);
    sa.sa_handler=sigchld_handler; sa.sa_flags=SA_RESTART|SA_NOCLDSTOP; sigaction(SIGCHLD,&sa,NULL);
    sa.sa_handler=sigterm_handler; sa.sa_flags=0; sigaction(SIGTERM,&sa,NULL); sigaction(SIGINT,&sa,NULL);
    unlink(CONTROL_PATH);
    ctx.server_fd=socket(AF_UNIX,SOCK_STREAM,0); if(ctx.server_fd<0){perror("socket");goto cleanup;}
    struct sockaddr_un addr; memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX; strncpy(addr.sun_path,CONTROL_PATH,sizeof(addr.sun_path)-1);
    if(bind(ctx.server_fd,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");goto cleanup;}
    if(listen(ctx.server_fd,8)<0){perror("listen");goto cleanup;}
    fprintf(stdout,"[supervisor] ready. rootfs=%s socket=%s\n",rootfs,CONTROL_PATH); fflush(stdout);
    while(!ctx.should_stop){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(ctx.server_fd,&rfds);
        struct timeval tv={.tv_sec=1,.tv_usec=0};
        int nready=select(ctx.server_fd+1,&rfds,NULL,NULL,&tv);
        if(nready<0){if(errno==EINTR)continue;perror("select");break;}
        if(nready==0)continue;
        int client_fd=accept(ctx.server_fd,NULL,NULL);
        if(client_fd<0){if(errno==EINTR)continue;perror("accept");continue;}
        control_request_t req; ssize_t n=read(client_fd,&req,sizeof(req));
        if(n==(ssize_t)sizeof(req)) handle_request(&ctx,client_fd,&req);
        close(client_fd);
    }
    fprintf(stdout,"[supervisor] shutting down...\n");
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *c=ctx.containers;
    while(c){if(c->state==CONTAINER_RUNNING||c->state==CONTAINER_STARTING){c->stop_requested=1;kill(c->host_pid,SIGTERM);}c=c->next;}
    pthread_mutex_unlock(&ctx.metadata_lock);
    sleep(2);
    pthread_mutex_lock(&ctx.metadata_lock); c=ctx.containers;
    while(c){if(c->state==CONTAINER_RUNNING||c->state==CONTAINER_STARTING)kill(c->host_pid,SIGKILL);c=c->next;}
    pthread_mutex_unlock(&ctx.metadata_lock);
cleanup:
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread,NULL);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *cur=ctx.containers;
    while(cur){container_record_t *next=cur->next;if(cur->log_pipe_read>=0)close(cur->log_pipe_read);if(cur->run_client_fd>=0)close(cur->run_client_fd);free(cur);cur=next;}
    ctx.containers=NULL; pthread_mutex_unlock(&ctx.metadata_lock);
    if(ctx.server_fd>=0){close(ctx.server_fd);unlink(CONTROL_PATH);}
    if(ctx.monitor_fd>=0)close(ctx.monitor_fd);
    pthread_mutex_destroy(&ctx.metadata_lock); g_ctx=NULL;
    fprintf(stdout,"[supervisor] exited cleanly.\n"); return 0;
}

/* ---------- Task 2: CLI run signal handling ---------- */
static void run_client_signal_handler(int sig){(void)sig;g_run_got_signal=1;}

static void forward_stop_to_supervisor(const char *container_id){
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0)return;
    struct sockaddr_un addr; memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX; strncpy(addr.sun_path,CONTROL_PATH,sizeof(addr.sun_path)-1);
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))<0){close(fd);return;}
    control_request_t req; memset(&req,0,sizeof(req));
    req.kind=CMD_STOP; strncpy(req.container_id,container_id,CONTAINER_ID_LEN-1);
    (void)write(fd,&req,sizeof(req));
    control_response_t resp; (void)read(fd,&resp,sizeof(resp)); close(fd);
}

/* ---------- send_control_request ---------- */
static int send_control_request(const control_request_t *req){
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0){perror("socket");return 1;}
    struct sockaddr_un addr; memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX; strncpy(addr.sun_path,CONTROL_PATH,sizeof(addr.sun_path)-1);
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr))<0){
        fprintf(stderr,"Cannot connect to supervisor at %s. Is the supervisor running?\n",CONTROL_PATH);
        close(fd); return 1;
    }
    if(write(fd,req,sizeof(*req))!=(ssize_t)sizeof(*req)){perror("write request");close(fd);return 1;}
    control_response_t resp; ssize_t n=read(fd,&resp,sizeof(resp));
    if(n<=0){fprintf(stderr,"No response from supervisor\n");close(fd);return 1;}
    printf("%s\n",resp.message);
    if(req->kind==CMD_LOGS){
        char buf[1024];
        while((n=read(fd,buf,sizeof(buf)))>0)(void)write(STDOUT_FILENO,buf,(size_t)n);
        close(fd); return(resp.status==0)?0:1;
    }
    if(req->kind==CMD_RUN){
        strncpy(g_run_container_id,req->container_id,CONTAINER_ID_LEN-1);
        struct sigaction sa; memset(&sa,0,sizeof(sa)); sigemptyset(&sa.sa_mask);
        sa.sa_handler=run_client_signal_handler;
        sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL);
        while(1){
            if(g_run_got_signal){
                g_run_got_signal=0;
                fprintf(stderr,"\n[run] caught signal - forwarding stop to supervisor\n");
                forward_stop_to_supervisor(g_run_container_id);
            }
            control_response_t final; n=read(fd,&final,sizeof(final));
            if(n==(ssize_t)sizeof(final)){
                printf("%s\n",final.message); close(fd);
                return final.exit_signal>0?128+final.exit_signal:final.exit_code;
            }
            if(n<=0)break;
        }
    }
    close(fd); return(resp.status==0)?0:1;
}

/* ---------- CLI commands ---------- */
static int cmd_start(int argc,char *argv[]){
    if(argc<5){fprintf(stderr,"Usage: %s start <id> <rootfs> <cmd> [opts]\n",argv[0]);return 1;}
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_START;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1); strncpy(req.rootfs,argv[3],PATH_MAX-1); strncpy(req.command,argv[4],CHILD_COMMAND_LEN-1);
    req.soft_limit_bytes=DEFAULT_SOFT_LIMIT; req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    if(parse_optional_flags(&req,argc,argv,5))return 1; return send_control_request(&req);
}
static int cmd_run(int argc,char *argv[]){
    if(argc<5){fprintf(stderr,"Usage: %s run <id> <rootfs> <cmd> [opts]\n",argv[0]);return 1;}
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_RUN;
    strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1); strncpy(req.rootfs,argv[3],PATH_MAX-1); strncpy(req.command,argv[4],CHILD_COMMAND_LEN-1);
    req.soft_limit_bytes=DEFAULT_SOFT_LIMIT; req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    if(parse_optional_flags(&req,argc,argv,5))return 1; return send_control_request(&req);
}
static int cmd_ps(void){control_request_t req;memset(&req,0,sizeof(req));req.kind=CMD_PS;return send_control_request(&req);}
static int cmd_logs(int argc,char *argv[]){
    if(argc<3){fprintf(stderr,"Usage: %s logs <id>\n",argv[0]);return 1;}
    control_request_t req;memset(&req,0,sizeof(req));req.kind=CMD_LOGS;strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);return send_control_request(&req);
}
static int cmd_stop(int argc,char *argv[]){
    if(argc<3){fprintf(stderr,"Usage: %s stop <id>\n",argv[0]);return 1;}
    control_request_t req;memset(&req,0,sizeof(req));req.kind=CMD_STOP;strncpy(req.container_id,argv[2],CONTAINER_ID_LEN-1);return send_control_request(&req);
}

int main(int argc,char *argv[]){
    if(argc<2){usage(argv[0]);return 1;}
    if(!strcmp(argv[1],"supervisor")){if(argc<3){fprintf(stderr,"Usage: %s supervisor <base-rootfs>\n",argv[0]);return 1;}return run_supervisor(argv[2]);}
    if(!strcmp(argv[1],"start"))return cmd_start(argc,argv);
    if(!strcmp(argv[1],"run"))  return cmd_run(argc,argv);
    if(!strcmp(argv[1],"ps"))   return cmd_ps();
    if(!strcmp(argv[1],"logs")) return cmd_logs(argc,argv);
    if(!strcmp(argv[1],"stop")) return cmd_stop(argc,argv);
    usage(argv[0]); return 1;
}
