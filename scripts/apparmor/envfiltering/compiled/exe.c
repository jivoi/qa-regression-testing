#include <gtk/gtk.h>
#include <stdlib.h>
int main (int argc, char *argv[]) {
  gtk_init (&argc, &argv);
  system("./child_exe");
}
