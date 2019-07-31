#ifndef SPEED_H
#define SPEED_H

#define MSECS(t) ((double)(t)/(2600000))

void print_results(const char *s, unsigned long long *t, size_t tlen);
unsigned long long average(unsigned long long *t, size_t tlen);
float std_deviation(float *data, int size);
#endif
