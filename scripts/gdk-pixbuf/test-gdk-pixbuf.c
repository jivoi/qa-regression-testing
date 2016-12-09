#include <gdk-pixbuf/gdk-pixbuf.h>

int main(int argc, char **argv) {
	GdkPixbuf* buf;
	int size = 180;
	GError* err = NULL;

/* glib before 2.36 (i.e. precise) requires g_type_init() to be called */
#ifndef GLIB_VERSION_2_36
	g_type_init();
#endif

	buf =  gdk_pixbuf_new_from_file_at_size(argv[1], size, size, &err);

	if (err)
		printf ("Gerror: %s\n", err->message);

	g_object_unref(buf);
	return 0;
}
