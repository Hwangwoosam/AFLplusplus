#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../include/afl-fuzz.h"

static afl_state_t * afl ;
static funcov_t * conf ;


/**
 * TODO.
 * - union & per trace => at the end of the fuzzing campaign.
 *      static cov_stat_t * cov_stats ; // save
 *      static unsigned int * trace_cov ; 
 *      map_elem_t trace_map[FUNCOV_MAP_SIZE] ;
*/

void
funcov_shm_deinit (afl_state_t * afl)   
{
    detatch_shm((void *)(afl->funcov.curr_stat)) ;
    remove_shm(afl->funcov.shmid) ;
}

void 
shm_deinit ()
{
    funcov_shm_deinit(afl) ;
    afl_shm_deinit(&afl->shm);
}

void
shm_init (afl_state_t * afl)    // TODO. if get/attatch shm failed?
{
    afl->funcov.shmid = get_shm(INIT, sizeof(cov_stat_t)) ;
    afl->funcov.curr_stat = attatch_shm(afl->funcov.shmid) ;
    memset(afl->funcov.curr_stat, 0, sizeof(cov_stat_t)) ;
}

void 
funcov_init (afl_state_t * init_afl)
{
    afl = init_afl ;
    conf = &(afl->funcov) ; // Q. position?
    if (afl->fsrv.use_stdin) afl->funcov.input_type = STDIN ;
    else afl->funcov.input_type = ARG_FILENAME ;

    if (afl->funcov.input_type == ARG_FILENAME) {
        sprintf(afl->funcov.input_file, "%s", afl->fsrv.out_file) ; // TODO. out_file path?
    }

    int position = -1 ;
    for (int i = strlen(afl->fsrv.target_path) - 1; i >= 0; i--) {
        if (afl->fsrv.target_path[i] == '/') {
            position = i ;
            break ;
        }
    }
    if (position > 0) {
        char dir_path[PATH_MAX] ;
        strncpy(dir_path, afl->fsrv.target_path, position) ; 
        dir_path[position] = '\0' ;
        sprintf(afl->funcov.bin_path, "%s/funcov_src/%s", dir_path, afl->fsrv.target_path + position + 1) ;
    }
    else {
        sprintf(afl->funcov.bin_path, "./funcov_src/%s", afl->fsrv.target_path) ;
    }

    if (access(afl->funcov.bin_path, X_OK) == -1) {
        PFATAL("could not find %s", afl->funcov.bin_path) ;
    }
    
    sprintf(afl->funcov.out_dir, "%s/funcov", afl->out_dir) ;

    // shm_init(afl) ;
}


static int stdin_pipe[2] ;
static int stdout_pipe[2] ;
static int stderr_pipe[2] ;

static int child_pid ;

void
timeout_handler (int sig)
{
    if (sig == SIGALRM) {
        perror("timeout") ;
        if (kill(child_pid, SIGINT) == -1) {
            // shm_deinit() ;
            PFATAL("timeout_handler: kill") ;
        }
    }
}

void
execute_target (void * mem, u32 len)
{
    alarm(3) ;

    if (conf->input_type == STDIN) {
        u32 s = write(stdin_pipe[1], mem, len) ;
        if (s != len) {
            // shm_deinit() ;
            PFATAL("funcov: short write") ;
        }
    }
    
    close(stdin_pipe[1]) ;

    dup2(stdin_pipe[0], 0) ;
    close(stdin_pipe[0]) ;

    close(stdout_pipe[0]) ;
    close(stderr_pipe[0]) ;

    dup2(stdout_pipe[1], 1) ;
    dup2(stderr_pipe[1], 2) ;

    // TODO. ASAN_OPTION
    char sancov_opt[BUF_SIZE];
    sprintf(sancov_opt,"ASAN_OPTIONS=coverage=1:coverage_dir=%s/sancov",conf->out_dir);

    if (conf->input_type == STDIN) {
        char * args[] = { conf->bin_path, (char *)0x0 } ;
        char * env[] = {sancov_opt,(char*)0x0};
        if (execve(conf->bin_path, args,env) == -1) {
            // shm_deinit() ;
            PFATAL("execute_target: execv") ;
        }
    } 
    else if (conf->input_type == ARG_FILENAME) {
        char * args[] = { conf->bin_path, conf->input_file, (char *)0x0 } ;
        if (execv(conf->bin_path, args) == -1) {
            // shm_deinit() ;
            PFATAL("execute_target: execv") ;
        }
    }
}

void
close_pipes ()
{   
    close(stdin_pipe[0]) ;
    close(stdin_pipe[1]) ;
    close(stdout_pipe[0]) ;
    close(stdout_pipe[1]) ;
    close(stderr_pipe[0]) ;
    close(stderr_pipe[1]) ;

}

int
run (void * mem, u32 len,int * pid_num)
{

    if (pipe(stdin_pipe) != 0) goto pipe_err ;
    if (pipe(stdout_pipe) != 0) goto pipe_err ;
    if (pipe(stderr_pipe) != 0) goto pipe_err ;

    child_pid = fork() ; 

    if (child_pid == 0) {
 
        execute_target(mem, len) ;
    }
    else if (child_pid > 0) {
        close_pipes() ;
    }
    else {
        PFATAL("run: fork") ;
    }
    *pid_num = child_pid;

    int exit_code ;
    wait(&exit_code) ;

    return exit_code ;

pipe_err:
    PFATAL("run: pipe") ;
}

void
parse_file_name (char * file_name, char * long_path)
{
    int position = -1 ;
    for (int i = strlen(long_path) - 1; i >= 0; i--) {
        if (long_path[i] == '/') {
            position = i ;
            break ;
        }
    } 
    if (position >= 0) {
        strcpy(file_name, long_path + position + 1) ;
    } 
    else strcpy(file_name, long_path) ;
}

int
find_fun_id (name_entry_t * func_names, char * callee_name)
{
    int found = 0 ;
    int fun_id = hash16(callee_name) ;
    for (int i = 0; i < FUNCOV_MAP_SIZE; i++) {
        if (fun_id >= FUNCOV_MAP_SIZE) fun_id = 0 ;
        if (func_names[fun_id].exist && strcmp(callee_name, func_names[fun_id].name) != 0) fun_id++ ;
        else {
            if (!func_names[fun_id].exist) {
                strcpy(func_names[fun_id].name, callee_name) ;
                func_names[fun_id].exist = 1 ;
            }
            found = 1 ;
            break ;
        }
    }
    if (!found) {
        // shm_deinit() ;
        PFATAL("Map overflow") ;
    }

    return fun_id ;
}

static int in_pipe[2];
static int out_pipe[2];
static int err_pipe[2];

void 
run_addr2line(char ** argv)
{
    close(in_pipe[1]);
    
    dup2(in_pipe[0],0);
    
    close(in_pipe[0]);
    close(out_pipe[0]);
    close(err_pipe[0]);

    dup2(out_pipe[1],1);
    dup2(err_pipe[1],2);
    
    execv(argv[0],argv);

    // shm_deinit();
    PFATAL("Failed to execute addr2line");
}

void 
save_addr2line_results(u8 ** seeds_per_func_map,char* file_path,name_entry_t * func_names,int seed_id)
{
    close(in_pipe[0]);
    close(err_pipe[0]);
    close(in_pipe[1]);
    close(out_pipe[1]);
    close(err_pipe[1]);

    FILE * w_fp = fopen(file_path,"wb");
    if(w_fp == 0x0){
        // shm_deinit();
        PFATAL("save_addr2line_results: fopen");
    }

    FILE * r_fp = fdopen(out_pipe[0],"rb");
    if(r_fp == 0x0){
        // shm_deinit();
        PFATAL("save_addr2line_results: fdopen");
    }

    fprintf(w_fp,"pc_val,callee\n");
    char buf[BUF_SIZE];
    char callee[BUF_SIZE];

    for(int cnt = 0; fgets(buf,BUF_SIZE,r_fp) != 0x0; cnt++){
        if(cnt %4 == 0){
            memset(callee,0,sizeof(char)*BUF_SIZE);
            
            strncpy(callee,buf,strlen(buf)-1);
            callee[strlen(buf)] ='\0';

        }else if(cnt %4 == 2){
            if(strcmp(callee,"main") == 0) continue;
            if(strcmp(callee,"??") == 0) continue;
            if(strcmp(buf,"??") == 0) continue;
            
            char* cov_string = alloc_printf("%s,%s",callee,buf);
            int fun_id = find_fun_id(func_names,cov_string);
            if(seeds_per_func_map[fun_id][seed_id] == 0){
                seeds_per_func_map[fun_id][seed_id] = 1;
            }else{
                free(cov_string);
                continue;
            }

            fprintf(w_fp,"%s,%s",callee,buf);
            free(cov_string);
        }
    }

    fclose(r_fp);
    fclose(w_fp);
}

void
get_funcnames_using_addr2line(u8 ** seeds_per_func_map,char* file_path,char ** argv, name_entry_t * func_names,int seed_id)
{
    if(pipe(in_pipe) != 0) goto pipe_err;
    if(pipe(out_pipe) != 0) goto pipe_err;
    if(pipe(err_pipe) != 0 ) goto pipe_err;

    int child_pid = fork();

    if(child_pid == 0){
        run_addr2line(argv);
    }
    else if(child_pid > 0){
        save_addr2line_results(seeds_per_func_map,file_path,func_names,seed_id);
    }else{
        // shm_deinit();
        PFATAL("translate_pc_values: fork");
    }

    wait(0x0);

    return ;

pipe_err:
    // shm_deinit();
    PFATAL("run: pipe");
}

void
write_covered_funs_csv(char * funcov_dir_path) 
{

    char input_filename[PATH_MAX] ;
    parse_file_name(input_filename, conf->input_file) ; // TODO. tokenize long path
    
    char funcov_file_path[PATH_MAX + 256] ;
    sprintf(funcov_file_path, "%s/%s.csv", funcov_dir_path, input_filename) ;

    FILE * fp = fopen(funcov_file_path, "wb") ;
    if (fp == 0x0) {
        // shm_deinit() ;
        PFATAL("write_covered_funs_csv: fopen") ;
    }

    fprintf(fp, "callee,pc_val\n") ; 
    // for (int i = 0; i < FUNCOV_MAP_SIZE; i++) {
        // if (conf->curr_stat->map[i].hit_count == 0) continue ; 
        // fprintf(fp, "%s\n", conf->curr_stat->map[i].cov_string) ; 
    // }

    fclose(fp) ;
}

static int stdin_pipe_san[2];
static int stdout_pipe_san[2];
static int stderr_pipe_san[2];

void
read_sancov_result(char* sancov_file_name,char* funcov_file_path){

    if (pipe(stdin_pipe_san) != 0) goto pipe_err ;
    if (pipe(stdout_pipe_san) != 0) goto pipe_err ;
    if (pipe(stderr_pipe_san) != 0) goto pipe_err ;

    int child = fork();

    if(child == 0){        
        close(stdin_pipe_san[1]);
        close(stdin_pipe_san[0]);
        close(stdout_pipe_san[0]);
        close(stderr_pipe_san[0]);

        dup2(stdout_pipe_san[1],1);
        dup2(stderr_pipe_san[1],2);


        char* args[] = {"sancov","-print",sancov_file_name,(char*)0x0};
        if(execv(args[0],args) == -1){
            PFATAL("read_sancov_result: execv %s",sancov_file_name);
        }

    }else if(child > 0){
        close(stdin_pipe_san[0]) ;
        close(stdin_pipe_san[1]) ;
        close(stdout_pipe_san[1]) ;
        close(stderr_pipe_san[0]) ;
        close(stderr_pipe_san[1]) ;

        FILE* fp = fopen(funcov_file_path,"wb");
        if(fp == 0x0){
            PFATAL("read_sancov_result: fopen");
            exit(1);
        }

        char buf[BUF_SIZE];
        int s = 0;
        while((s = read(stdout_pipe_san[0],buf,BUF_SIZE)) > 0){
            if(fwrite(buf,1,s,fp) != s){
                PFATAL("read_sancov_result: fwrite");
            }
        }
        close(stdout_pipe_san[0]) ;
        fclose(fp);
        
    }else{
          PFATAL("read_sancov_result: fork") ;
    }
    wait(0x0);
    return ;

pipe_err:
    PFATAL("run: pipe");
}

int
funcov (void * mem, u32 len, u8 * seed_path) 
{
    signal(SIGALRM, timeout_handler) ;
    strcpy(afl->funcov.input_file, seed_path) ;
    
    int child_pid;
    int exit_code = run(mem, len,&child_pid) ;
    // printf("child_pid: %d\n",child_pid);

    char sancov_file_name[PATH_MAX+64];
    char* ptr = strrchr(conf->bin_path,'/');

    sprintf(sancov_file_name, "%s/sancov/%s.%d.sancov",conf->out_dir,ptr+1,child_pid);
    // printf("file: %s\n",sancov_file_name);

    char input_filename[PATH_MAX] ;
    parse_file_name(input_filename, conf->input_file) ; // TODO. tokenize long path
    
    char funcov_file_path[PATH_MAX + 256] ;
    sprintf(funcov_file_path, "%s/funcov_per_seed/%s.csv", conf->out_dir, input_filename) ;
    read_sancov_result(sancov_file_name,funcov_file_path);
    // write_covered_funs_csv(funcov_dir_path) ;

    return 0 ;
}

void
read_queued_inputs (u8 ** seeds_per_func_map, char ** seed_names, name_entry_t * func_names)
{
    DIR * dir_ptr = 0x0 ;
    struct dirent * entry = 0x0 ;

    char src_dir[PATH_MAX] ;
    sprintf(src_dir, "%s/funcov_per_seed", conf->out_dir) ;
    if ((dir_ptr = opendir(src_dir)) == 0x0) {
        // shm_deinit() ;
        PFATAL("Failed to open %s", src_dir) ;
    }

    u32 seed_id = 0 ;
    
    while ((entry = readdir(dir_ptr)) != 0x0) {
        if (entry->d_name[0] != '.') {

            char seed_path[PATH_MAX] ;
            sprintf(seed_path, "%s/%s", src_dir, entry->d_name) ;
            strcpy(seed_names[seed_id], entry->d_name) ;
            
            char ** addr2line_argv = (char**) malloc(sizeof(char*)*(FUNCOV_MAP_SIZE + 4));

            addr2line_argv[0] = alloc_printf("/usr/bin/addr2line");
            addr2line_argv[1] = alloc_printf("-fe");
            addr2line_argv[2] = alloc_printf("%s",conf->bin_path);

            int addr2line_argc = 3;

            FILE * fp = fopen(seed_path, "rb") ;
            if (fp == 0x0) {
                // shm_deinit() ;
                PFATAL("Failed to open %s", entry->d_name) ;
            }

            char buf[BUF_SIZE] ;
            int first = 1 ;

            
            while (fgets(buf, BUF_SIZE, fp) != NULL) {
                if (first) {
                    first = 0 ; 
                    continue ;
                }
                //TODO
                char* ptr = strtok(buf,",");
                addr2line_argv[addr2line_argc++] = alloc_printf("%s",ptr);
                ptr = strtok(NULL,",");
                addr2line_argv[addr2line_argc++] = alloc_printf("%s",ptr);
                
            }

            fclose(fp) ;

            get_funcnames_using_addr2line(seeds_per_func_map, seed_path, addr2line_argv,func_names ,seed_id);
            
            seed_id++;
            for(int i = 0; i < addr2line_argc; i++){
                free(addr2line_argv[i]);
            }

            free(addr2line_argv);
        }
    }
    
    if (closedir(dir_ptr) == -1) {
        // shm_deinit() ;
        PFATAL("Failed to open %s\n", src_dir) ;
    }

}

void
write_seeds_per_func_map (u8 ** seeds_per_func_map, char ** seed_names, name_entry_t * func_names)
{
    for (int fun_id = 0; fun_id < FUNCOV_MAP_SIZE; fun_id++) {
        if (func_names[fun_id].exist) {
            char dst_path[PATH_MAX] ;
            sprintf(dst_path, "%s/seed_per_func/%s.csv", conf->out_dir, func_names[fun_id].name) ;
            
            FILE * fp = fopen(dst_path, "wb") ;
            if (fp == 0x0) {
                // shm_deinit() ;
                PFATAL("Failed to open %s", dst_path) ;
            }
            for (u32 seed_id = 0; seed_id < afl->queued_items; seed_id++) {
                if (seeds_per_func_map[fun_id][seed_id]) {
                    fprintf(fp, "%s\n", seed_names[seed_id]) ;
                }
            }
            fclose(fp) ;
        }
    }
}

int 
get_seeds_for_func ()
{
    name_entry_t * func_names = malloc(sizeof(name_entry_t) * FUNCOV_MAP_SIZE) ;
    if (func_names == 0x0) goto alloc_failed ;
    memset(func_names, 0, sizeof(name_entry_t) * FUNCOV_MAP_SIZE) ;
    
    u8 ** seeds_per_func_map = (u8 **) malloc(sizeof(u8 *) * FUNCOV_MAP_SIZE) ; // TODO. too large map size
    if (seeds_per_func_map == 0x0) goto alloc_failed ;

    for (u32 i = 0; i < FUNCOV_MAP_SIZE; i++) {
        seeds_per_func_map[i] = (u8 *) malloc(sizeof(u8) * afl->queued_items) ;
        if (seeds_per_func_map[i] == 0x0) goto alloc_failed ;
        memset(seeds_per_func_map[i], 0, sizeof(u8) * afl->queued_items) ;
    }

    char ** seed_names = (char **) malloc(sizeof(char *) * afl->queued_items) ;

    for (u32 i = 0; i < afl->queued_items; i++) {
        seed_names[i] = (char *) malloc(sizeof(char) * PATH_MAX) ;
        if (seed_names[i] == 0x0) goto alloc_failed ;
    }
    
    read_queued_inputs(seeds_per_func_map, seed_names, func_names) ;
    write_seeds_per_func_map(seeds_per_func_map, seed_names, func_names) ;

    for (u32 i = 0; i < FUNCOV_MAP_SIZE; i++) {
        free(seeds_per_func_map[i]) ;
    }
    for (u32 i = 0; i < afl->queued_items; i++) {
        free(seed_names[i]) ;
    }
    free(seeds_per_func_map) ;
    free(seed_names) ;
    free(func_names) ;

    return 0 ;

alloc_failed:
    // shm_deinit() ;
    PFATAL("Failed to allocate memory for a seed map") ;
}