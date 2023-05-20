#ifndef __CFG_PARSER_H__
#define __CFG_PARSER_H__

#include "fw_config.h"
#include "state.h"

void fill_table_from_file(struct State *state, struct nf_config *config);

#endif