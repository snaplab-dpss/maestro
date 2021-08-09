#pragma once

#include <sstream>
#include <iostream>

namespace ParallelSynthesizer {

namespace Colors {

typedef std::string Color;

const Color RESET = "\033[0m";
const Color BLACK = "\033[30m";
const Color RED = "\033[31m";
const Color RED_BRIGHT = "\u001b[31;1m";
const Color GREEN = "\033[32m";
const Color YELLOW = "\033[33m";
const Color BLUE = "\033[34m";
const Color MAGENTA = "\033[35m";
const Color CYAN = "\033[36m";
const Color WHITE = "\033[37m";
const Color BOLD = "\033[1m";
}

class Logger {

public:
  enum Level {
    DEBUG,
    LOG,
    WARNING,
    ERROR
  };

  std::ostream stream;

  static Level MINIMUM_LOG_LEVEL;

  static Logger log();
  static Logger debug();
  static Logger warn();
  static Logger error();

private:
  Colors::Color color;
  Level level;

private:
  Logger(const Level &_level) : stream(nullptr), level(_level) {
    switch (_level) {
      case LOG:
        stream.rdbuf(std::cout.rdbuf());
        color = Colors::WHITE;
        break;
      case DEBUG:
        stream.rdbuf(std::cerr.rdbuf());
        color = Colors::GREEN;
        break;
      case WARNING:
        stream.rdbuf(std::cerr.rdbuf());
        color = Colors::CYAN;
        break;
      case ERROR:
        stream.rdbuf(std::cerr.rdbuf());
        color = Colors::RED_BRIGHT;
        break;
      default:
        stream.rdbuf(std::cerr.rdbuf());
        color = Colors::WHITE;
    }
  }

  Logger(const Logger &logger) : Logger(logger.level) {}

  template <typename T> friend Logger &operator<<(Logger &logger, T &&t);

  template <typename T> friend Logger &operator<<(Logger &&logger, T &&t);
};

template <typename T> Logger &operator<<(Logger &logger, T &&t) {
  if (logger.level < Logger::MINIMUM_LOG_LEVEL)
    return logger;

  //logger.stream << logger.color;
  logger.stream << std::forward<T>(t);
  //logger.stream << Colors::RESET;
  logger.stream.flush();

  return logger;
}

template <typename T> Logger &operator<<(Logger &&logger, T &&t) {
  return logger << std::forward<T>(t);
}
}
