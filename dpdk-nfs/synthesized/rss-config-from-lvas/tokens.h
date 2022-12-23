#pragma once

namespace ParallelSynthesizer {
namespace Tokens {

const std::string OPTIONAL = "?";

namespace Access {
const std::string START = "BEGIN ACCESS";
const std::string END = "END ACCESS";
const std::string ID = "id";
const std::string SRC_DEVICE = "src_device";
const std::string DST_DEVICE = "dst_device";
const std::string SUCCESS = "success";
const std::string OPERATION = "operation";
const std::string OBJECT = "object";
}

namespace Operations {
const std::string READ = "READ";
const std::string WRITE = "WRITE";
const std::string CREATE = "CREATE";
const std::string VERIFY = "VERIFY";
const std::string UPDATE = "UPDATE";
const std::string DESTROY = "DESTROY";
const std::string NOP = "NOP";
const std::string INIT = "INIT";
}

namespace Argument {
const std::string START = "BEGIN ARGUMENT";
const std::string END = "END ARGUMENT";
const std::string TYPE = "type";
const std::string EXPRESSION = "expression";
}

namespace ArgumentType {
const std::string READ = "read";
const std::string WRITE = "write";
const std::string RESULT = "result";
}

namespace Expression {
const std::string START = "BEGIN EXPRESSION";
const std::string END = "END EXPRESSION";
}

namespace PacketDependencies {
const std::string START = "BEGIN PACKET DEPENDENCIES";
const std::string END = "END PACKET DEPENDENCIES";
}

namespace Chunk {
const std::string START = "BEGIN CHUNK";
const std::string END = "END CHUNK";

const std::string LAYER = "layer";
const std::string PROTOCOL = "protocol";
const std::string DEPENDENCY = "dependency";
}

namespace Metadata {
const std::string START = "BEGIN METADATA";
const std::string END = "END METADATA";

const std::string INTERFACE = "interface";
const std::string FILE = "file";
}

namespace CallPathConstraint {
const std::string START = "BEGIN CALL PATHS CONSTRAINT";
const std::string END = "END CALL PATHS CONSTRAINT";
}

namespace CallPathInfo {
const std::string START = "BEGIN CALL PATH INFO";
const std::string END = "END CALL PATH INFO";
const std::string CALL_PATH = "call_path";
const std::string TYPE = "type";
const std::string ID = "id";
}

namespace CallPathInfoType {
const std::string SOURCE = "source";
const std::string PAIR = "pair";
}

}
}
