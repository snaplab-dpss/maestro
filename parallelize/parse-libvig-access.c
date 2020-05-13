#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <r3s.h>

typedef struct {
    unsigned layer;
    unsigned proto;
    R3S_pf_t *dep;
    unsigned dep_sz;
} libvig_access_t;

bool match_token(char *str, const char* token) {
    return strncmp(str, token, strlen(token)) == 0;
}

bool is_dep_in_array(R3S_pf_t pf, R3S_pf_t *pfs, unsigned sz) {
    for (int i = 0; i < sz; i++)
        if (pfs[i] == pf) return true;
    return false;
}

void unique_save_access(
    libvig_access_t access,
    libvig_access_t **accesses,
    unsigned *sz
) {
    libvig_access_t *curr;

    if (*sz > 0) {
        for (unsigned i = 0; i < *sz; i++) {
            curr = &((*accesses)[i]);
            if (curr->layer  != access.layer)  continue;
            if (curr->proto  != access.proto)  continue;
            if (curr->dep_sz != access.dep_sz) continue;

            bool eq = true;
            for (int j = 0; j < curr->dep_sz; j++) {
                if (!is_dep_in_array(curr->dep[j], access.dep, access.dep_sz)) {
                    eq = false;
                    break;
                }
            }
            if (!eq) continue;

            return;
        }
    }

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

void unique_save_dep(libvig_access_t *access, R3S_pf_t pf) {
    assert(access != NULL);

    if (is_dep_in_array(pf, access->dep, access->dep_sz))
        return;
    
    access->dep_sz++;
    access->dep = (R3S_pf_t*) realloc(
        access->dep,
        sizeof(R3S_pf_t) * access->dep_sz
    );
    access->dep[access->dep_sz - 1] = pf;
}

void parse_dep(libvig_access_t *access, unsigned dep) {
    // IPv4
    if (access->layer == 3 && access->proto == 0x0800) {
        if (dep >= 12 && dep <= 15) {
            unique_save_dep(access, R3S_PF_IPV4_SRC);
        }

        else if (dep >= 16 && dep <= 19) {
            unique_save_dep(access, R3S_PF_IPV4_DST);
        }

        else {
            printf("[WARNING] Unknown packet header field at byte %u\n", dep);
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
            unique_save_dep(access, R3S_PF_TCP_SRC);
        }

        else if (dep >= 2 && dep <= 3) {
            unique_save_dep(access, R3S_PF_TCP_DST);
        }
    }
}

void parse_libvig_access_file(char* path, libvig_access_t **accesses, unsigned *sz) {
    FILE *fp;
    
    char *line = NULL;
    char *line_ptr;
    size_t len = 0;
    ssize_t read_len;

    libvig_access_t curr;

    *sz = 0;
    *accesses = NULL;
    
    if ((fp = fopen(path, "r")) == NULL) {
        printf("[ERROR] Unable to open %s\n", path);
        exit(1);
    }

    line = NULL;
    while ((read_len = getline(&line, &len, fp)) > 0) {
        if (len == 1) break;
        line[read_len - 1] = 0;

        if (match_token(line, "BEGIN")) {          
            curr.dep_sz = 0;
            curr.dep = NULL;
        } else if (match_token(line, "END")) {
            unique_save_access(curr, accesses, sz);
        } else if (match_token(line, "layer")) {
            line_ptr = line + strlen("layer");
            while (*line_ptr == ' ') line_ptr++;

            sscanf(line_ptr, "%u", &curr.layer);

        } else if (match_token(line, "proto")) {
            line_ptr = line + strlen("proto");
            while (*line_ptr == ' ') line_ptr++;

            sscanf(line_ptr, "%u", &curr.proto);

        } else if (match_token(line, "dep")) {
            line_ptr = line + strlen("dep");
            while (*line_ptr == ' ') line_ptr++;

            unsigned dep;

            sscanf(line_ptr, "%u", &dep);
            parse_dep(&curr, dep);

        } else {
            printf("[ERROR] Unknown token in line %s\n", line);
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

    libvig_access_t *accesses;
    unsigned sz;

    parse_libvig_access_file(libvig_access_out, &accesses, &sz);

    printf("Unique accesses (%u):\n", sz);
    for (unsigned i = 0; i < sz; i++) {
        for (unsigned idep = 0; idep < accesses[i].dep_sz; idep++) {
            printf("* %s\n", R3S_pf_to_string(accesses[i].dep[idep]));
        }
    }
}