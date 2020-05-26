#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <r3s.h>

#include "./libvig_access.h"
#include "./constraint.h"

typedef struct {
    libvig_accesses_t accesses;
    constraints_t     constraints;
} parsed_data_t;

typedef enum {
    INIT,
    ACCESS,
    CONSTRAINT,
    SMT
} parser_state_t;

void parsed_data_init(parsed_data_t *data) {
    libvig_accesses_init(&(data->accesses));
    constraints_init(&(data->constraints));
}

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

char* consume_token(char *str, const char* token) {
    char *str_ptr;
    bool result = strncmp(str, token, strlen(token)) == 0;

    if (!result) return NULL;

    str_ptr = str + strlen(token);
    while (*str_ptr == ' ') str_ptr++;

    return str_ptr;
}

void parse_symbol(Z3_context ctx, Z3_symbol symbol)
{
    switch (Z3_get_symbol_kind(ctx, symbol)) {
    case Z3_INT_SYMBOL:
        printf("INT #%d", Z3_get_symbol_int(ctx, symbol));
        break;
    case Z3_STRING_SYMBOL:
        printf("STRING %s", Z3_get_symbol_string(ctx, symbol));
        break;
    default:
        printf("error\n");
        exit(1);
    }
}

typedef struct {
    Z3_ast   select;
    unsigned index;
} pf_ast_t;

void traverse_ast_and_retrieve_selects(Z3_context ctx, Z3_ast ast, pf_ast_t **selects, size_t *sz) {
    switch (Z3_get_ast_kind(ctx, ast)) {
    
    case Z3_NUMERAL_AST: {
        Z3_sort sort = Z3_get_sort(ctx, ast);
        printf("NUMERAL %s : %s\n", Z3_get_numeral_string(ctx, ast), Z3_sort_to_string(ctx, sort));
        break;
    }

    case Z3_APP_AST: {
        Z3_app app = Z3_to_app(ctx, ast);
        Z3_func_decl decl = Z3_get_app_decl(ctx, app);

        printf("FUNC DECL %s\n", Z3_func_decl_to_string(ctx, decl));

        Z3_symbol name = Z3_get_decl_name(ctx, decl);
        unsigned num_fields = Z3_get_app_num_args(ctx, app);

        if (strcmp(Z3_get_symbol_string(ctx, name), "select") == 0) {
            printf("\n!***** BAM *****!\n");
            printf("ast  : %s\n", Z3_ast_to_string(ctx, ast));
            
            Z3_ast array_ast = Z3_get_app_arg(ctx, app, 0);
            Z3_ast index_ast = Z3_get_app_arg(ctx, app, 1);

            assert(Z3_get_ast_kind(ctx, array_ast) == Z3_APP_AST);

            Z3_app array_app = Z3_to_app(ctx, array_ast);
            Z3_func_decl array_decl = Z3_get_app_decl(ctx, array_app);
            Z3_symbol array_name = Z3_get_decl_name(ctx, array_decl);

            if (strcmp(Z3_get_symbol_string(ctx, array_name), "packet_chunks") == 0) {
                printf("SYMBOL %s\n",
                    Z3_get_symbol_string(ctx, array_name)
                );

                printf("parging argument...\n");
                assert(Z3_get_ast_kind(ctx, index_ast) == Z3_NUMERAL_AST);

                Z3_sort index_sort = Z3_get_sort(ctx, index_ast);
                unsigned index;

                // TODO: append to pf_ast_t array
                Z3_get_numeral_uint(ctx, index_ast, &index);

                printf("index: %u\n", index);
            }

        } else {
            for (unsigned i = 0; i < num_fields; i++) {
                traverse_ast_and_retrieve_selects(ctx, Z3_get_app_arg(ctx, app, i), selects, sz);
            }
        }


        break;
    }

    default:
        printf("error\n");
        exit(1);
    }
}

void parse_libvig_access_file(char* path, parsed_data_t *data) {
    FILE *fp;
    
    char *line = NULL;
    char *line_ptr;
    size_t len = 0;
    ssize_t read_len;

    libvig_access_t curr_access;
    smt_t curr_smt;

    parser_state_t state = INIT;

    if ((fp = fopen(path, "r")) == NULL) {
        printf("[ERROR] Unable to open %s\n", path);
        exit(1);
    }

    line = NULL;
    while ((read_len = getline(&line, &len, fp)) > 0) {
        if (len == 1) break;
        line[read_len - 1] = 0;

        switch (state) {
            case INIT:
                if (consume_token(line, "BEGIN ACCESS")) {
                    deps_init(&(curr_access.deps));
                    state = ACCESS;
                } else if (consume_token(line, "BEGIN CONSTRAINT")) {
                    state = CONSTRAINT;
                } else {
                    printf("[ERROR] Unknown token in state INIT: \"%s\"\n", line);
                    exit(1);
                }

                break;
            
            case ACCESS:
                if (consume_token(line, "END ACCESS")) {
                    if (curr_access.deps.sz)
                        libvig_accesses_append_unique(curr_access, &(data->accesses));
                    state = INIT;
                } else if (((line_ptr = consume_token(line, "id")))) {
                    sscanf(line_ptr, "%u", &curr_access.id);

                } else if ((line_ptr = consume_token(line, "device"))) {
                    sscanf(line_ptr, "%u", &curr_access.device);

                } else if ((line_ptr = consume_token(line, "object"))) {
                    sscanf(line_ptr, "%u", &curr_access.obj);

                } else if ((line_ptr = consume_token(line, "layer"))) {
                    sscanf(line_ptr, "%u", &curr_access.layer);

                } else if ((line_ptr = consume_token(line, "proto"))) {
                    sscanf(line_ptr, "%u", &curr_access.proto);

                } else if ((line_ptr = consume_token(line, "dep"))) {
                    unsigned offset;
                    sscanf(line_ptr, "%u", &offset);

                    dep_t dep = dep_from_offset(offset, curr_access);
                    deps_append_unique(&(curr_access.deps), dep);

                } else {
                    printf("[ERROR] Unknown token in state ACCESS: \"%s\"\n", line);
                    exit(1);
                }

                break;

            case CONSTRAINT:
                if (consume_token(line, "END CONSTRAINT")) {
                    constraints_append(&(data->constraints), data->accesses, curr_smt);
                    free(curr_smt.query);
                    state = INIT;

                } else if (consume_token(line, "BEGIN SMT")) {
                    curr_smt.query = (char*) malloc(sizeof(char));
                    curr_smt.query[0] = '\0';
                    curr_smt.query_sz = 1;
                    state = SMT;

                } else if ((line_ptr = consume_token(line, "first"))) {
                    sscanf(line_ptr, "%u", &curr_smt.first_access_id);

                } else if ((line_ptr = consume_token(line, "second"))) {
                    sscanf(line_ptr, "%u", &curr_smt.second_access_id);

                } else {
                    printf("[ERROR] Unknown token in state CONSTRAINT: \"%s\"\n", line);
                    exit(1);
                }

                break;
            
            case SMT:
                if (consume_token(line, "END SMT")) {
                    state = CONSTRAINT;
                } else {
                    curr_smt.query = (char*) realloc(
                        curr_smt.query,
                        sizeof(char) * (curr_smt.query_sz + read_len)
                    );

                    strncpy(curr_smt.query+curr_smt.query_sz-1, line, read_len - 1);

                    curr_smt.query_sz += read_len;
                    curr_smt.query[curr_smt.query_sz - 2] = '\n';
                    curr_smt.query[curr_smt.query_sz - 1] = '\0';
                }

                break;
            
            default:
                printf("[ERROR] Unknown state: (%u)\n", state);
                exit(1);
        }
    }

    free(line);
    fclose(fp);

    if (state != INIT) {
        printf("[ERROR] Final state not INIT: (%u)\n", state);
        exit(1);
    }
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("[ERROR] Missing arguments.");
        printf("Please provide a libvig-access-out.txt file location\n");
        return 1;
    }

    char* libvig_access_out = argv[1];

    parsed_data_t data;
    parsed_data_init(&data);

    parse_libvig_access_file(libvig_access_out, &data);

    unsigned curr_device;
    bool curr_device_set = false;

    for (unsigned i = 0; i < data.accesses.sz ; i++) {
        printf("Device %u\n", data.accesses.accesses[i].device);
        printf("Object %u\n", data.accesses.accesses[i].obj);

        for (unsigned idep = 0; idep < data.accesses.accesses[i].deps.sz; idep++) {
            if (data.accesses.accesses[i].deps.deps[idep].pf_is_set)
                printf("    %s\n", R3S_pf_to_string(data.accesses.accesses[i].deps.deps[idep].pf));
            else
                printf("  * %s\n", data.accesses.accesses[i].deps.deps[idep].error_descr);
        }
    }
}