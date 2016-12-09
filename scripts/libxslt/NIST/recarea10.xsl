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
            margin-top="0.1in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="0.1in"
               margin-top="0.1in"
               margin-right="1.0in"
               margin-bottom="1.0in">
            </fo:region-body>
           </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
           <fo:block-container
             inline-progression-dimension="auto"
             block-progression-dimension = "0.4in"
             overflow="scroll"
             space-after.optimum = "0.4in">
            <fo:block
              padding-before="0.1in"
              padding-after="0.1in"
              padding-start="0.1in"
              padding-end="0.1in"
              background-color="red"><xsl:value-of select="block1"/>
            </fo:block>
          </fo:block-container>
          <fo:block-container
             inline-progression-dimension="auto"
             block-progression-dimension = "0.5in">
            <fo:block
              padding-before="0.1in"
              padding-after="0.1in"
              padding-start="0.1in"
              padding-end="0.1in"
              background-color="red"><xsl:value-of select="block2"/>
            </fo:block>
          </fo:block-container>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>

