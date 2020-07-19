#pragma once

namespace ParallelSynthesizer {
namespace Tokens {

const std::string ACCESS_START = "BEGIN ACCESS";
const std::string ACCESS_END = "END ACCESS";

const std::string ID = "id";
const std::string DEVICE = "device";
const std::string OBJECT = "object";
const std::string LAYER = "layer";
const std::string PROTOCOL = "protocol";
const std::string DEPENDENCY = "dependency";
const std::string OPERATION = "operation";

const std::string CONSTRAINT_START = "BEGIN CONSTRAINT";
const std::string CONSTRAINT_END = "END CONSTRAINT";

const std::string FIRST = "first";
const std::string SECOND = "second";

const std::string STATEMENT_START = "BEGIN SMT";
const std::string STATEMENT_END = "END SMT";

namespace Operations {

const std::string READ = "read";
const std::string WRITE = "write";
const std::string NOP = "nop";
const std::string INIT = "init";

}

}
}
