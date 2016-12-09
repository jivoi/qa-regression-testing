<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

<xsl:output indent="yes"/>

<xsl:template match = "TEST">
 <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
    <fo:layout-master-set>
        <fo:simple-page-master
            page-height="11in" 
            page-width="8.5in"
            margin-left="1.0in"
            margin-top="0.5in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.1in"
               margin-right="2.0in"
               margin-bottom="1.0in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
            <fo:block 
               space-after.optimum = "0.2in"
               text-align="center">
               The areas below should increase in size from top to bottom.
            </fo:block>             
            <fo:block
               space-after.optimum="0.15in"
               start-indent="0.9in"
               end-indent="0.9in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-after.optimum="0.15in"
               start-indent="0.8in"
               end-indent="0.8in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-after.optimum="0.15in"
               start-indent="0.7in"
               end-indent="0.7in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-after.optimum="0.15in"
               start-indent="0.6in"
               end-indent="0.6in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-after.optimum="0.15in"
               start-indent="0.5in"
               end-indent="0.5in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-after.optimum="0.15in"
               start-indent="0.4in"
               end-indent="0.4in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-before.optimum="0.2in"
               start-indent="0.3in"
               end-indent="0.3in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-before.optimum="0.2in"
               start-indent="0.2in"
               end-indent="0.2in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
           <fo:block
               space-before.optimum="0.2in"
               start-indent="0.1in"
               end-indent="0.1in"
               padding-before="0.1in"
               padding-after="0.1in"
               background-color="red">
           </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>