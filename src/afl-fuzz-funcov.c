#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h> 
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>

#include "afl-fuzz.h"
#include "config.h"
#include "debug.h"

static pid_t child;

static int in_pipes[2] ;
static int out_pipes[2] ;
static int err_pipes[2] ;

int shmid = 0;
int flag_err = 0;

unsigned short funcov_hash(char* name){
  unsigned hash_val = 0;
  
  int length = strlen(name);
  
  for(int i = 0; i < length; i++){
    hash_val = (unsigned char)name[i] + 23131*hash_val;
  }

  return (hash_val&0xffff);
}

int get_shmid(shm_state_t state, int type_size){
    int shmid;

    if(state == INIT){
        shmid = shmget(IPC_PRIVATE,type_size,IPC_CREAT|IPC_EXCL|0600);
        if(shmid < 0){
            PFATAL("get_shmid() failed\n");
        }

        u8* id_str = alloc_printf("%d",shmid);
        setenv(FUNCOV_SHM_KEY,id_str,1);
        ck_free(id_str);

    }else{
        char* id_str = getenv(FUNCOV_SHM_KEY);
        shmid = atoi(id_str);
    }

    return shmid;
}

void * attach_shm(int shmid){
    void * ptr = shmat(shmid,0,0);
    
    if(ptr == (void*)(-1)){
        fprintf(stderr,"shm_attach failed\n");
        exit(1);
    }

    return ptr;
}

void dettach_shm(void * shm_addr){
    if(shmdt(shm_addr) == -1){
      fprintf(stderr,"Shmdt failed\n");
      exit(1);
    }
}

void remove_shm(int shmid){
    if(shmctl(shmid,IPC_RMID,0) == -1){
        perror("remove_shm() failed\n");
        exit(1);
    }
}

void funcov_init(afl_state_t * afl){
  
  if(afl->fsrv.use_stdin) afl->funcov_info.input_type = 1;
  
  afl->funcov_info.seed_num = 0;

  if(strstr(afl->fsrv.target_path,"a.out") != NULL)
  {
    strcpy(afl->funcov_info.binary,"afl_funcov");

  }else{
    char funcov_name[MAX_ADDR];
    sprintf(funcov_name,"%s_funcov",afl->fsrv.target_path); 
    
    strcpy(afl->funcov_info.binary,funcov_name);
  }

  if(access(afl->funcov_info.binary,X_OK) == -1){
    PFATAL("could not find %s",afl->funcov_info.binary);
  }

  sprintf(afl->funcov_info.out_dir,"%s/funcov",afl->out_dir);

  funcov_shm_init(afl);
}

void add_seed(union_coverage_t* union_coverage,char* seed_name,int hash_val){

  if(union_coverage->seed_list[hash_val] != NULL){

    union_pair_t* node;
    for(node = union_coverage->seed_list[hash_val]; node->next != NULL; node = node->next);

    union_pair_t* new_seed = (union_pair_t*)malloc(sizeof(union_pair_t));
    strcpy(new_seed->seed_name,seed_name);
    new_seed->next = NULL;
    node->next = new_seed;

  }else{
    union_coverage->seed_list[hash_val] = (union_pair_t*)malloc(sizeof(union_pair_t));
    
    strcpy(union_coverage->seed_list[hash_val]->seed_name,seed_name);
    union_coverage->seed_list[hash_val]->next = NULL;
  }
}

void get_coverage(afl_state_t * afl,char** seed_name_list,union_coverage_t* union_coverage){
  char* input_path = (char*)malloc(sizeof(char)*(strlen(afl->funcov_info.out_dir) +20));
  sprintf(input_path,"%s/funcov_per_coverage",afl->funcov_info.out_dir);

  for(int i = 0; i < afl->funcov_info.seed_num; i++){
    char seed_file[MAX_ADDR];
    sprintf(seed_file,"%s/%s",input_path,seed_name_list[i]);
    FILE *fp = fopen(seed_file,"rb");

    if(fp == 0x0){
      fprintf(stderr,"funcov get_coverage: fopen failed\n");
      exit(1);
    }

    char buf[MAX_BUF];
    while(fgets(buf,MAX_BUF,fp) != 0x0){
      unsigned short hash_val = funcov_hash(buf);
      int len = strlen(buf);
      buf[len-1] ='\0';
      int idx = hash_val;

      do{
        if(union_coverage->func_name[idx] != NULL){

          if(strcmp(union_coverage->func_name[idx],buf) == 0){
            add_seed(union_coverage,seed_name_list[i],idx);
            break;
          }
        }else{

          union_coverage->func_name[hash_val] =(char*)malloc(sizeof(char)*(len+1));
    
          strncpy(union_coverage->func_name[hash_val],buf,len);
          union_coverage->func_name[hash_val][len] ='\0';

          add_seed(union_coverage,seed_name_list[i],idx);

          break;
        }

        i++;

        if(i >= HASH_SIZE){
          i = 0;
        }

      }while(i != hash_val);

    }

    fclose(fp);
  }

  free(input_path);
}

void get_seed_list(afl_state_t* afl,char** seed_name_list){
  
  char seed_dir[MAX_ADDR];
  sprintf(seed_dir,"%s/funcov_per_coverage",afl->funcov_info.out_dir);
 
  DIR* dir = opendir(seed_dir);
  struct dirent * dp;

  int idx = 0;

  if(dir == NULL){
    fprintf(stderr,"funcov-get_seed_list: opendir failed\n");
    exit(1);
  }else{
    while(dp = readdir(dir)){

      if(dp->d_name[0] == '.'){
        continue;
      }

      seed_name_list[idx] = (char*)malloc(sizeof(char)*(dp->d_reclen + 1));
      strncpy(seed_name_list[idx],dp->d_name,dp->d_reclen);
      seed_name_list[idx][dp->d_reclen] = '\0';

      idx++;
    }

    closedir(dir);
  }

}

void get_union(afl_state_t* afl){

  union_coverage_t* union_coverage = (union_coverage_t*)malloc(sizeof(union_coverage_t));
  memset(union_coverage,0,sizeof(union_coverage_t));

  char* seed_name_list[afl->funcov_info.seed_num];
  get_seed_list(afl,seed_name_list);
  get_coverage(afl,seed_name_list,union_coverage);

  char* union_path = (char*)malloc(sizeof(char)*(strlen(afl->funcov_info.out_dir) + 32));
  sprintf(union_path,"%s/seed_per_func/seed_per_func.csv",afl->funcov_info.out_dir);

  FILE *fp = fopen(union_path,"w+");

  if(fp == 0x0){
    fprintf(stderr,"funcov-get_union: fopen failed\n");
    fclose(fp);
    return ;
  }

  for(int i = 0; i < HASH_SIZE; i++){
    if(union_coverage->func_name[i] == NULL) continue;
  
    fprintf(fp,"\"%s\"\n",union_coverage->func_name[i]);

    union_pair_t* node = union_coverage->seed_list[i];

    while(node != NULL){
      fprintf(fp,",\"%s\"\n",node->seed_name);
      union_pair_t* prev = node;
      node = node->next;
      free(prev);
    }
    
    free(union_coverage->func_name[i]);
  }

  free(union_coverage);
}

void funcov_shm_deinit(afl_state_t* afl){
  //translate
  get_union(afl);
  
  dettach_shm(afl->funcov_info.shm_info);
  remove_shm(afl->funcov_info.shmid);
}

void funcov_shm_init(afl_state_t * afl){
  afl->funcov_info.shmid = get_shmid(INIT,sizeof(SHM_info_t));
  afl->funcov_info.shm_info = attach_shm(afl->funcov_info.shmid);

  memset(afl->funcov_info.shm_info,0,sizeof(SHM_info_t));
}

int execute_prog(afl_state_t* afl,void* mem, u32 len){

  if(afl->funcov_info.input_type == 1){

    u32 s = write(in_pipes[1],mem,len);
    if(s < len){
      fprintf(stderr,"(funcov_run)short write\n");
      exit(1);
    }

  }

  close(in_pipes[1]);
  
  dup2(in_pipes[0],0);

  close(in_pipes[0]);
  close(out_pipes[0]);
  close(err_pipes[0]);

  dup2(out_pipes[1],1);
  // dup2(err_pipes[1],2);
  
  if(afl->funcov_info.input_type == 0){
    char* args[] = {afl->funcov_info.binary,afl->fsrv.out_file,(char*)0x0};
    if(execv(afl->funcov_info.binary,args) == -1){
      perror("[excute_prog] - Execution Error\n");
  	  return -1;
    }
  
  }else{
  
    char* args[] = {afl->funcov_info.binary,(char*)0x0};
    
    if(execv(afl->funcov_info.binary,args) == -1){
      perror("[excute_prog] - Execution Error\n");
  	  return -1;
    }
  }

  return 0;
}

int run(afl_state_t* afl,void* mem, u32 len){
  
  if (pipe(in_pipes) != 0) goto pipe_err;
  if (pipe(out_pipes) != 0) goto pipe_err;
	if (pipe(err_pipes) != 0) goto pipe_err;

  child = fork();
  afl->fsrv.funcov_pid = child;

  int ret ;

  if(child == 0){
    execute_prog(afl,mem,len);
  }else if(child > 0){

    close(in_pipes[0]);
    close(in_pipes[1]);
    close(err_pipes[0]);
    close(err_pipes[1]);
    close(out_pipes[0]);
    close(out_pipes[1]);

  }else{
    PFATAL("funcov fork() failed");
  }

  wait(&ret);
  return ret;

pipe_err:
  PFATAL("(RUN): Pipe error");
}
/*
int translate_addr(afl_state_t* afl){
  
  char** argv = (char**)malloc(sizeof(char*)*(indiv_coverage->func_cnt + 4));

  argv[0] = (char*)malloc(sizeof(char)*MAX_ADDR);
  strcpy(argv[0],"/usr/bin/addr2line");

  argv[1] = (char*)malloc(sizeof(char)*4);
  strcpy(argv[1],"-e");

  argv[2] = (char*)malloc(sizeof(char)*MAX_ADDR);
  strcpy(argv[2],afl->funcov_info.binary);

  argv[indiv_coverage->func_cnt +3] = (char*)0x0;

  int index = 0;

  for(int i = 0; i < HASH_SIZE; i++){
    if(indiv_coverage->func_list[i] != NULL){

      table_trans[index] = i;

      int len = strlen(indiv_coverage->func_list[i]);
      int addr2_cnt = 0;
      for(int j = 0; j < len; j++){
        if(indiv_coverage->func_list[i][j] == ','){
          addr2_cnt++;
          if(addr2_cnt == 2){
            argv[index + 3] = &indiv_coverage->func_list[i][j+1];
            break;
          } 
        }
      }

      index ++;
    }
  }

  if(pipe(out_pipes) != 0){
    fprintf(stderr,"(Translate) Pipe Error\n");
    goto err_case;
  }

  pid_t addr2line;
  addr2line = fork();
  int ret;
  if(addr2line == 0){
    close(out_pipes[0]);
    dup2(out_pipes[1],1);

    execv(argv[0],argv);
    fprintf(stderr,"(translate) execv failed\n");
    return -1;
  }else if(addr2line > 0){
    close(out_pipes[1]);
    wait(&ret);

    if(ret == -1){
      goto err_case;  
    }

    FILE * fp = fdopen(out_pipes[0],"rb");
    
    if(fp == 0x0){
      fprintf(stderr,"(translate) fdopen failed\n");
      goto err_case;
    }

    char buf[MAX_BUF];
    int number = 0;
    while(fgets(buf,MAX_BUF,fp) != 0x0){
      line_number[table_trans[number]] = (char*)malloc(sizeof(char)*(strlen(buf) + 1));
      strcpy(line_number[table_trans[number]],buf);
      number++;
    }

  }else{
    fprintf(stderr,"fork error\n");
    goto err_case;
  }

  free(argv);
  return 0;

  err_case:
    free(argv);
    return 1;
}
*/
void save_result(afl_state_t* afl){
  char* file_name = strrchr(afl->funcov_info.input,'/');
  if(afl->funcov_info.shm_info->cnt == 0){
    printf("(%s)shm_cnt: %d\n",file_name,afl->funcov_info.shm_info->cnt);
    printf("shmid: %d\n",afl->funcov_info.shmid);
    exit(1);
  }
  char* idv_path = (char*)malloc(sizeof(char)*(strlen(afl->funcov_info.out_dir) + strlen(file_name) +30));
  sprintf(idv_path,"%s/funcov_per_coverage/%s.csv",afl->funcov_info.out_dir,file_name+1);

  FILE* fp = fopen(idv_path,"w+");

  if(fp == NULL){
    fprintf(stderr,"(save_result):failed to open idv file\n");
    fclose(fp);
    return ;
  }

  fprintf(fp,"callee,caller,caller_line,hit,line number\n");
  for(int j = 0; j < HASH_SIZE; j++){  
    if(afl->funcov_info.shm_info->func_coverage[j].hit_cnt != 0){
      fprintf(fp,"%s\n",afl->funcov_info.shm_info->func_coverage[j].func_line);
    }
  }
  free(idv_path);
  fclose(fp);
}

void funcov(char* input_path,afl_state_t * afl,void* mem,u32 len){
  memset(afl->funcov_info.shm_info,0,sizeof(SHM_info_t));

  afl->funcov_info.seed_num++;

  strcpy(afl->funcov_info.input,input_path);

  int ret = run(afl,mem,len);
  
  if(ret == -1){
    flag_err = 1;
  }

  save_result(afl);

  return ;
}
