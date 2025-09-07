#pragma once
#ifndef R15_PROTECTION_H
#define R15_PROTECTION_H

#include <stdint.h>

/* Layer boundary symbols from linker script */
extern char __layer1_start;
extern char __layer1_end;
extern char __layer2_start;
extern char __layer2_end;
extern char __layer3_start;
extern char __layer3_end;

/* Memory protection levels */
#define MEMORY_LAYER_1  ((uint64_t)&__layer1_start)   /* hw data & attest */
#define MEMORY_LAYER_2  ((uint64_t)&__layer2_start)   /* NSKernel reset rollbk */
#define MEMORY_LAYER_3  ((uint64_t)&__layer3_start)   /* Core sections */

/* r15 protection boundary values */
#define R15_BOUNDARY_1  MEMORY_LAYER_2  /* Block access below nskernel sections */
#define R15_BOUNDARY_2  MEMORY_LAYER_3  /* Block access below core sections */

/* r15 save/restore macros */
#define SAVE_R15(var) \
    asm volatile ("movq %%r15, %0" : "=m" (var) : : "memory")

#define RESTORE_R15(var) \
    asm volatile ("movq %0, %%r15" : : "m" (var) : "memory")

#define SET_R15_BOUNDARY(boundary) \
    asm volatile ("movq %0, %%r15" : : "r" ((uint64_t)(boundary)) : "memory")

/* Three-layer protection macros */

/* Layer 1: Allow all memory access (no r15 restriction) */
void __unsan_Layer1_enter(uint64_t* __saved_r15) {
  SAVE_R15(*__saved_r15);
  asm volatile ("movq %0, %%r15" : : "r" ((uint64_t)(0)) : "memory");
}

/* Layer 2: Block access to dynamic/system sections */
void __unsan_Layer2_enter(uint64_t* __saved_r15) {
  SAVE_R15(*__saved_r15);
  SET_R15_BOUNDARY(R15_BOUNDARY_1);
}

/* Layer 3: Block access to dynamic/system and nskernel sections */
void __unsan_Layer3_enter(uint64_t* __saved_r15) {
  SAVE_R15(*__saved_r15);
  SET_R15_BOUNDARY(R15_BOUNDARY_2);
}

/* EXIT */
void __unsan_Layer_exit(uint64_t* __saved_r15) {
  RESTORE_R15(*__saved_r15);
}

#define __unsan_layer1_enter() \
  uint64_t __saved_r15; __unsan_Layer1_enter(&__saved_r15);
#define __unsan_layer2_enter() \
  uint64_t __saved_r15; __unsan_Layer2_enter(&__saved_r15);
#define __unsan_layer3_enter() \
  uint64_t __saved_r15; __unsan_Layer3_enter(&__saved_r15);
#define __unsan_layer_exit()   \
  __unsan_Layer_exit(&__saved_r15);
#endif
