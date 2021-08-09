#include "logger.h"

namespace ParallelSynthesizer {

Logger Logger::log() { return Logger(Logger::LOG); }

Logger Logger::debug() { return Logger(Logger::DEBUG); }

Logger Logger::warn() { return Logger(Logger::WARNING); }

Logger Logger::error() { return Logger(Logger::ERROR); }

Logger::Level Logger::MINIMUM_LOG_LEVEL = Logger::WARNING;
}
