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
               space-after.optimum="0.1in"
               border-before-width="0.03in"
               border-after-width="0.03in"
               border-start-width="0.03in"
               border-end-width="0.03in"
               border-end-style="solid"
               border-before-style="solid"
               border-start-style="solid"
               border-after-style="solid"
               padding-before="0.5in"
               padding-after="0.5in"
               padding-end="0.5in"
               padding-start="0.5in">Should have two child areas
              <fo:block
               space-after.optimum="0.1in"
               border-before-width="0.03in"
               border-after-width="0.03in"
               border-start-width="0.03in"
               border-end-width="0.03in"
               border-end-style="solid"
               border-before-style="solid"
               border-start-style="solid"
               border-after-style="solid"
               padding-before="0.2in"
               padding-after="0.2in"
               padding-end="0.4in"
               padding-start="0.4in">
              </fo:block>
              <fo:block
               border-before-width="0.03in"
               border-after-width="0.03in"
               border-start-width="0.03in"
               border-end-width="0.03in"
               border-end-style="solid"
               border-before-style="solid"
               border-start-style="solid"
               border-after-style="solid"
               padding-before="0.2in"
               padding-after="0.2in"
               padding-end="0.2in"
               padding-start="0.2in">Should have two child areas
                 <fo:block 
                  space-after.optimum="0.05in"
                  border-before-width="0.03in"
                  border-after-width="0.03in"
                  border-start-width="0.03in"
                  border-end-width="0.03in"
                  border-end-style="solid"
                  border-before-style="solid"
                  border-start-style="solid"
                  border-after-style="solid"
                  padding-before="0.3in"
                  padding-after="0.3in"
                  padding-end="0.1in"
                  padding-start="0.1in">
                 </fo:block>
                 <fo:block
                  space-after.optimum="0.03in"
                  border-before-width="0.03in"
                  border-after-width="0.03in"
                  border-start-width="0.03in"
                  border-end-width="0.03in"
                  border-end-style="solid"
                  border-before-style="solid"
                  border-start-style="solid"
                  border-after-style="solid"
                  padding-before="0.3in"
                  padding-after="0.3in"
                  padding-end="0.1in"
                  padding-start="0.1in">
                 </fo:block>
              </fo:block>
            </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
