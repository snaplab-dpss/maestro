#ifndef DSOS_IOPORT_H
#define DSOS_IOPORT_H

#include <stddef.h>

/* Used for PCI */

static inline uint8_t dsos_inb(uint16_t port) {
  uint8_t ret;
  asm volatile("inb %1, %0" : "=a"(ret) : "dN"(port));
  return ret;
}

static inline uint16_t dsos_inw(uint16_t port) {
  uint16_t ret;
  asm volatile("inw %1, %0" : "=a"(ret) : "dN"(port));
  return ret;
}

static inline uint32_t dsos_inl(uint16_t port) {
  uint32_t ret;
  asm volatile("inl %1, %0" : "=a"(ret) : "dN"(port));
  return ret;
}

static inline void dsos_outb(uint8_t val, uint16_t port) {
  asm volatile("outb %0, %1" : : "a"(val), "dN"(port));
}

static inline void dsos_outw(uint16_t val, uint16_t port) {
  asm volatile("outw %0, %1" : : "a"(val), "dN"(port));
}

static inline void dsos_outl(uint32_t val, uint16_t port) {
  asm volatile("outl %0, %1" : : "a"(val), "dN"(port));
}

#endif
