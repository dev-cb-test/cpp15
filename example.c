#include <stdlib.h>
#include <stdio.h>

struct MyStruct {
  char* buf;
};

// Use-after-free of `buf` field.
static void test0100() {
  struct MyStruct* s = (struct MyStruct*)malloc(sizeof(struct MyStruct));
  s->buf = malloc(0x1000);
  sprintf(s->buf, "kevwozere: %d\n", 100);
  free(s->buf);
  sprintf(s->buf, "kevwozere: %d\n", 101);  // BAD: use-after-free
  free(s);
}

static void writebuf(struct MyStruct *s, int id) {
  sprintf(s->buf, "kevwozere: %d\n", id);
}

// Like test0100, but with a stack-allocated struct.
// Also, the UAF is in a sub-routine now.
static void test0200() {
  struct MyStruct s;
  s.buf = malloc(0x1000);
  sprintf(s.buf, "kevwozere: %d\n", 200);
  free(s.buf);
  writebuf(&s, 201);  // BAD: use-after-free
}

static void freeBuf(char* buf) {
  if (buf) {
    free(buf);
  }
}

// Like test0100, but with an indirect call to `free()`.
static void test0300() {
  struct MyStruct* s = (struct MyStruct*)malloc(sizeof(struct MyStruct));
  s->buf = malloc(0x1000);
  sprintf(s->buf, "kevwozere: %d\n", 300);
  freeBuf(s->buf);
  writebuf(s, 301);  // BAD: use-after-free
  free(s);
}

static void test0400_sub(struct MyStruct* s) {
  sprintf(s->buf, "kevwozere: %d\n", 400);
  freeBuf(s->buf);
  // BAD: s->buf contains a dangling pointer on function exit
}

static void test0400() {
  struct MyStruct* s = (struct MyStruct*)malloc(sizeof(struct MyStruct));
  s->buf = malloc(0x1000);
  test0400_sub(s);
  writebuf(s, 301);  // BAD: use-after-free (due to bug in test0400_sub)
  free(s);
}

// Correct version of test0400_sub.
static void test0500_sub(struct MyStruct* s) {
  sprintf(s->buf, "kevwozere: %d\n", 400);
  freeBuf(s->buf);
  s->buf = 0;  // GOOD: dangling pointer is zeroed.
}

// Correct version of test0400.
static void test0500() {
  struct MyStruct* s = (struct MyStruct*)malloc(sizeof(struct MyStruct));
  s->buf = malloc(0x1000);
  test0500_sub(s);
  free(s);
}

int main() {
  test0100();
  test0200();
  test0300();
  test0400();
  test0500();
  return 0;
}
