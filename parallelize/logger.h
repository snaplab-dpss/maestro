#pragma once

#include <sstream>
#include <iostream>

namespace ParallelSynthesizer {

namespace Colors {

typedef std::string Color;

const Color RESET = "\033[0m";
const Color BLACK = "\033[30m";
const Color RED = "\033[31m";
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
        DEBUG, LOG, WARNING, ERROR
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

    Logger(const Level& _level) : stream(nullptr), level(_level) {
        stream.rdbuf(std::cout.rdbuf());

        switch (_level) {
            case DEBUG:
                color = Colors::GREEN;
                break;
            case LOG:
                color = Colors::WHITE;
                break;
            case WARNING:
                color = Colors::CYAN;
                break;
            case ERROR:
                color = Colors::RED;
                break;
            default:
                color = Colors::WHITE;
        }
    }

    Logger(const Logger& logger) : Logger(logger.level) {}

    template <typename T>
    friend Logger& operator<<(Logger& logger, T&& t);

    template <typename T>
    friend Logger& operator<<(Logger&& logger, T&& t);
};

template <typename T>
Logger& operator<<(Logger& logger, T&& t) {
    if (logger.level < Logger::MINIMUM_LOG_LEVEL)
        return logger;

    logger.stream << logger.color;
    logger.stream << std::forward<T>(t);
    logger.stream << Colors::RESET;
    logger.stream.flush();

    return logger;
}

template <typename T>
Logger& operator<<(Logger&& logger, T&& t) {
    return logger << std::forward<T>(t);
}

}
