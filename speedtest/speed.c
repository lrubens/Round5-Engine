#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include "speed.h"
#include "config.h"

float std_deviation(float *data, int size){
  float sum = 0.0, mean, standardDeviation = 0.0;
  int i;
  for(i = 0; i < size; ++i){
    sum += data[i];
  }
  mean = sum / size;
  // printf("%f", mean);
  for(i = 0; i < size; ++i)
    standardDeviation += pow(data[i] - mean, 2);
  return sqrt(standardDeviation / size);
}

static int cmp_llu(const void *a, const void *b) {
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen) {
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

unsigned long long average(unsigned long long *t, size_t tlen) {
  unsigned long long acc=0;
  size_t i;

  for(i=0;i<tlen;i++)
    acc += t[i];

  return acc/(tlen);
}

void print_results(const char *s, unsigned long long *t, size_t tlen) {
  unsigned long long tmp;

  printf("%s\n", s);

  tmp = median(t, tlen);
#ifdef USE_RDPMC
  printf("median: %llu cycles\n", tmp);
#else
  printf("median: %llu ticks @ 2.6 GHz (%.4g msecs)\n", tmp, MSECS(tmp));
#endif

  tmp = average(t, tlen);
#ifdef USE_RDPMC
  printf("average: %llu cycles\n", tmp);
#else
  printf("average: %llu ticks @ 2.6 GHz (%.4g msecs)\n", tmp, MSECS(tmp));
#endif

  printf("\n");
}
