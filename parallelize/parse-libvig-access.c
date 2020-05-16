#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <r3s.h>

typedef struct {
    unsigned offset;
    R3S_pf_t pf;
    bool     pf_is_set;
    char     error_descr[50];
} dep_t;

typedef struct {
    unsigned layer;
    unsigned proto;
    dep_t    *dep;
    unsigned dep_sz;
} libvig_access_t;

typedef struct {
    libvig_access_t *accesses;
    unsigned        sz;
    unsigned        device;
} execution_t;

void warn(const char* description) {
    printf("[WARNING] %s\n", description);
}

void invalid_rss_opt(const char* pf) {
    char pre[21] = "Invalid RSS option: ";
    
    unsigned pre_sz = strlen(pre);
    unsigned pf_sz  = strlen(pf);
    unsigned msg_sz = pre_sz + pf_sz + 1;

    char *msg = (char*) malloc(sizeof(char) * msg_sz);
    snprintf(msg, msg_sz, "%s%s", pre, pf);
    
    warn(msg);
    free(msg);
}

void libvig_access_print(libvig_access_t la) {
    printf("layer %u\n", la.layer);
    printf("proto %u\n", la.proto);
    for (unsigned i = 0; i < la.dep_sz; i++) {
        if (la.dep[i].pf_is_set)
            printf("dep   %s\n", R3S_pf_to_string(la.dep[i].pf));
    }
}

bool match_token(char *str, const char* token) {
    return strncmp(str, token, strlen(token)) == 0;
}

bool is_dep_in_array(dep_t dep, dep_t *deps, unsigned sz) {
    for (unsigned i = 0; i < sz; i++)
        if (
            (dep.pf_is_set == deps[i].pf_is_set)
            && (!dep.pf_is_set || (dep.pf == deps[i].pf))
        ) return true;
    return false;
}

bool libvig_access_equals(libvig_access_t l1, libvig_access_t l2) {
    if (l1.layer  != l2.layer)  return false;
    if (l1.proto  != l2.proto)  return false;
    if (l1.dep_sz != l2.dep_sz) return false;

    for (unsigned j = 0; j < l1.dep_sz; j++)
        if (!is_dep_in_array(l1.dep[j], l2.dep, l2.dep_sz))
            return false;
    
    for (unsigned j = 0; j < l2.dep_sz; j++)
        if (!is_dep_in_array(l2.dep[j], l1.dep, l1.dep_sz))
            return false;

    return true;    
}

bool is_access_in_array(libvig_access_t access, libvig_access_t *accesses, unsigned sz) {
    for (unsigned i = 0; i < sz; i++)
        if (libvig_access_equals(access, accesses[i]))
            return true;
    return false;
}

void unique_save_execution(
    execution_t execution,
    execution_t **executions,
    unsigned    *sz
) {
    execution_t *curr;

    for (unsigned i = 0; i < *sz; i++) {
        curr = &((*executions)[i]);

        if (curr->device != execution.device) continue;
        if (curr->sz     != execution.sz)     continue;
        
        bool eq = true;
        
        for(unsigned j = 0; j < execution.sz; j++) {
            if (!is_access_in_array(
                execution.accesses[j],
                curr->accesses,
                curr->sz)
            ) {
                eq = false;
                break;
            }
        }

        if (!eq) continue;

        return;
    }

    *sz += 1;
    *executions = (execution_t*) realloc(
        *executions,
        sizeof(execution_t) * (*sz));
    curr = &((*executions)[*sz - 1]);

    curr->accesses = execution.accesses;
    curr->device   = execution.device;
    curr->sz       = execution.sz;
}

void unique_save_access(
    libvig_access_t access,
    libvig_access_t **accesses,
    unsigned *sz
) {
    libvig_access_t *curr;

    if (is_access_in_array(access, *accesses, *sz))
        return;

    *sz += 1;
    *accesses = (libvig_access_t*) realloc(
        *accesses,
        sizeof(libvig_access_t) * (*sz));
    curr = &((*accesses)[*sz - 1]);

    curr->layer  = access.layer;
    curr->proto  = access.proto;
    curr->dep_sz = access.dep_sz;
    curr->dep    = access.dep;
}

void unique_save_dep(libvig_access_t *access, dep_t dep) {
    assert(access != NULL);

    if (is_dep_in_array(dep, access->dep, access->dep_sz))
        return;
    
    access->dep_sz++;
    access->dep = (dep_t*) realloc(
        access->dep,
        sizeof(dep_t) * access->dep_sz
    );
    access->dep[access->dep_sz - 1] = dep;
}

void parse_dep(libvig_access_t *access, unsigned dep) {
    dep_t store_dep;

    store_dep.offset = dep;
    store_dep.pf_is_set = false;
    store_dep.error_descr[0] = 0;

    // IPv4
    if (access->layer == 3 && access->proto == 0x0800) {

        if (dep == 9) {
            sprintf(store_dep.error_descr, "IPv4 protocol");
        }

        else if (dep >= 12 && dep <= 15) {
            store_dep.pf = R3S_PF_IPV4_SRC;
            store_dep.pf_is_set = true;
        }

        else if (dep >= 16 && dep <= 19) {
            store_dep.pf = R3S_PF_IPV4_DST;
            store_dep.pf_is_set = true;
        }

        else if (dep >= 20) {
            sprintf(store_dep.error_descr, "IPv4 options");
        }

        else {
            sprintf(
                store_dep.error_descr,
                "Unknown IPv4 field at byte %u\n",
                dep
            );
        }
    }

    // IPv6
    else if (access->layer == 3 && access->proto == 0x86DD) {

    }

    // VLAN
    else if (access->layer == 3 && access->proto == 0x8100) {

    }

    // TCP
    else if (access->layer == 4 && access->proto == 0x06) {
        if (dep >= 0 && dep <= 1) {
            store_dep.pf = R3S_PF_TCP_SRC;
            store_dep.pf_is_set = true;
        }

        else if (dep >= 2 && dep <= 3) {
            store_dep.pf = R3S_PF_TCP_DST;
            store_dep.pf_is_set = true;
        }

        else {
            sprintf(
                store_dep.error_descr,
                "Unknown TCP field at byte %u\n",
                dep
            );
        }
    }

    // UDP
    else if (access->layer == 4 && access->proto == 0x11) {
        if (dep >= 0 && dep <= 1) {
            store_dep.pf = R3S_PF_UDP_SRC;
            store_dep.pf_is_set = true;
        }

        else if (dep >= 2 && dep <= 3) {
            store_dep.pf = R3S_PF_UDP_DST;
            store_dep.pf_is_set = true;
        }

        else {
            sprintf(
                store_dep.error_descr,
                "Unknown UDP field at byte %u\n",
                dep
            );
        }
    }

    unique_save_dep(access, store_dep);
}

void parse_libvig_access_file(char* path, execution_t **executions, unsigned *sz) {
    FILE *fp;
    
    char *line = NULL;
    char *line_ptr;
    size_t len = 0;
    ssize_t read_len;

    libvig_access_t curr_access;
    execution_t curr_execution;

    *sz = 0;
    *executions = NULL;
    
    if ((fp = fopen(path, "r")) == NULL) {
        printf("[ERROR] Unable to open %s\n", path);
        exit(1);
    }

    line = NULL;
    while ((read_len = getline(&line, &len, fp)) > 0) {
        if (len == 1) break;
        line[read_len - 1] = 0;

        if (match_token(line, "BEGIN EXECUTION")) {
            curr_execution.sz = 0;
            curr_execution.accesses = NULL;

        } else if (match_token(line, "END EXECUTION")) {
            if (curr_execution.sz)
                unique_save_execution(curr_execution, executions, sz);

        } else if (match_token(line, "BEGIN ACCESS")) {
            curr_access.dep_sz = 0;
            curr_access.dep = NULL;
        
        } else if (match_token(line, "END ACCESS")) {
            if (curr_access.dep_sz)
                unique_save_access(curr_access, &curr_execution.accesses, &curr_execution.sz);

        } else if (match_token(line, "device")) {
            line_ptr = line + strlen("device");
            while (*line_ptr == ' ') line_ptr++;

            sscanf(line_ptr, "%u", &curr_execution.device);

        } else if (match_token(line, "layer")) {
            line_ptr = line + strlen("layer");
            while (*line_ptr == ' ') line_ptr++;

            sscanf(line_ptr, "%u", &curr_access.layer);

        } else if (match_token(line, "proto")) {
            line_ptr = line + strlen("proto");
            while (*line_ptr == ' ') line_ptr++;

            sscanf(line_ptr, "%u", &curr_access.proto);

        } else if (match_token(line, "dep")) {
            line_ptr = line + strlen("dep");
            while (*line_ptr == ' ') line_ptr++;

            unsigned dep;

            sscanf(line_ptr, "%u", &dep);
            parse_dep(&curr_access, dep);

        } else {
            printf("[ERROR] Unknown token: \"%s\"\n", line);
            exit(1);
        }
    }

    free(line);
    fclose(fp);
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("[ERROR] Missing arguments.");
        printf("Please provide a libvig-access-out.txt file location\n");
        return 1;
    }

    char* libvig_access_out = argv[1];

    execution_t *executions;
    unsigned sz;

    parse_libvig_access_file(libvig_access_out, &executions, &sz);

    for (unsigned i = 0; i < sz; i++) {
        printf("\nDevice %u\n", executions[i].device);
        printf("Unique accesses (%u):\n", executions[i].sz);
        for (unsigned j = 0; j < executions[i].sz; j++) {
            for (unsigned idep = 0; idep < executions[i].accesses[j].dep_sz; idep++) {
                if (executions[i].accesses[j].dep[idep].pf_is_set)
                    printf("    %s\n", R3S_pf_to_string(executions[i].accesses[j].dep[idep].pf));
                else
                    printf("  * %s\n", executions[i].accesses[j].dep[idep].error_descr);
            }
        }
    }
}