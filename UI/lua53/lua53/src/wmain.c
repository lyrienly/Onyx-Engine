#include <windows.h>
#include <stdlib.h>

extern int main(int, char **);

int PASCAL WinMain(HINSTANCE hinst, HINSTANCE hprev, LPSTR cmdline, int ncmdshow)
{
  int rc;

  extern int __argc;
  extern char** __argv;

  rc = main(__argc, __argv);

  return rc;
}
