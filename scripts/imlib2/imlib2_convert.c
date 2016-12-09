/**********************************

imlib2 test program

Based on example code found here:
http://docs.enlightenment.org/api/imlib2/html/

cc imlib2_convert.c -o imlib2_convert `imlib2-config --cflags` `imlib2-config --libs`

***********************************/

#define X_DISPLAY_MISSING 1

#include <stdlib.h>
#include <string.h>
#include <Imlib2.h>

/* main program */
int main(int argc, char **argv)
{
  /* an image handle */
  Imlib_Image image;
  Imlib_Load_Error error;
  
  /* if we provided < 2 arguments after the command - exit */
  if (argc != 3) exit(1);
  /* load the image */
  image = imlib_load_image(argv[1]);
  /* if the load was successful */
  if (image)
    {
      char *tmp;
      /* set the image we loaded as the current context image to work on */
      imlib_context_set_image(image);
      /* set the image format to be the format of the extension of our last */
      /* argument - i.e. .png = png, .tif = tiff etc. */
      tmp = strrchr(argv[2], '.');
      if(tmp)
         imlib_image_set_format(tmp + 1);
      /* save the image */
      imlib_save_image_with_error_return(argv[2],&error);
      exit(error);
    }
  else
    exit(1);
}

