#ifndef OPTIONS_H_
#define OPTIONS_H_

typedef struct {
  char *optname;
  char *parent;
  char *description;
  char *acceptablevalues;
  int type;

  void *data;

} CEServerOption, *PCEServerOption;

void handleGetOptions(int currentsocket);
void handleGetOption(int currentsocket);
void handleSetOption(int currentsocket);

char *getOptionValue(PCEServerOption o);

#endif
