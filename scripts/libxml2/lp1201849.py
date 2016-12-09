#!/usr/bin/python
from io import BytesIO
from lxml import etree
import tempfile, os

xml='''<root>
<child name='one' />
<child name='two' />
</root>
'''

document = etree.iterparse(BytesIO(xml), events=('end',), tag='root')
for action, elem in document:
 print("%s: %s" % (action, elem.tag))

tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testlib-")
fn = os.path.join(tempdir, "test.xml")

file(fn, 'w').write(xml)

document = etree.iterparse(fn, events=('end',), tag='root')
for action, elem in document:
 print("%s: %s" % (action, elem.tag))
