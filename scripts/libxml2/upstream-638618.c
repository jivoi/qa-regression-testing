/*
 * https://bugzilla.altlinux.org/attachment.cgi?id=4732
 * https://bugzilla.gnome.org/show_bug.cgi?id=638618
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=622358
 * https://bugs.launchpad.net/libxml2/+bug/686363
 *
 * To compile:
 * gcc ./upstream-638618.c -o upstream-638618 `xml2-config --cflags` `xml2-config --libs`
 */
#include <string.h>
#include <libxml/SAX2.h>

static void *called_func, *called_data;
#define	unset	((void *)0xbadc0ded)

static void ctxt_error_func(void *p, xmlErrorPtr e)
{
	called_func = ctxt_error_func;
	called_data = p;
}
#define ctxt_error_data	((void *)0xdeadbeef)

static void structured_error_func(void *p, xmlErrorPtr e)
{
	called_func = structured_error_func;
	called_data = p;
}
#define	structured_error_data	((void *)0xcafef00d)

int test_error_handler(int set_cef, int set_sef)
{
	void *expected_func = unset;
	void *expected_data = unset;
	int rc;

	xmlParserCtxtPtr ctxt = xmlCreateDocParserCtxt((const xmlChar *) "1");
	if (!ctxt) {
		perror("xmlCreateMemoryParserCtxt");
		return 1;
	}

	memset(ctxt->sax, 0, sizeof(*ctxt->sax));
	ctxt->sax->initialized = XML_SAX2_MAGIC;

	if (set_cef) {
		ctxt->sax->serror = expected_func = ctxt_error_func;
		ctxt->userData = expected_data = ctxt_error_data;
	}

	if (set_sef) {
		xmlSetStructuredErrorFunc(structured_error_data,
			structured_error_func);
		if (!set_cef) {
			expected_func = structured_error_func;
			expected_data = structured_error_data;
		}
	} else
		xmlSetStructuredErrorFunc(NULL, NULL);

	called_func = unset;
	called_data = unset;
	xmlParseDocument(ctxt);
	rc = expected_func != called_func || expected_data != called_data;

	if (ctxt->myDoc)
		xmlFreeDoc(ctxt->myDoc);
	xmlFreeParserCtxt(ctxt);

	return rc;
}

int main(void)
{
	return test_error_handler(0, 0) + test_error_handler(0, 1) +
		test_error_handler(1, 0) + test_error_handler(1, 1);
}
