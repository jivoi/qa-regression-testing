<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

<xsl:output indent="yes"/>

<xsl:template match = "TEST">
 <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
    <fo:layout-master-set>
        <fo:simple-page-master
            page-height="4.0in" 
            page-width="4.0in"
            margin-left="0.5in"
            margin-top="0.5in"
            margin-bottom="0.5in"
            margin-right="0.5in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="0.5in"
               margin-top="0.5in"
               margin-right="0.5in"
               margin-bottom="0.5in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
              <fo:block
               text-align="center"
               border-before-width="0.02in"                
               border-after-width="0.02in"
               border-end-width="0.02in"
               border-start-width="0.02in"
               border-end-style="solid" 
               border-start-style="solid" 
               border-after-style="solid" 
               border-before-style="solid"
               padding-before="0.02in"
               padding-after="0.02in"
               padding-start="0.02in"
               padding-end="0.02in"
               background-color="red">
               All page sizes should be 4 inches by 4 inches.  This
               text should appear on the first page.
             </fo:block>
              <fo:block
               keep-with-previous.within-page="always"
               text-align="center"
               border-before-width="0.02in"                
               border-after-width="0.02in"
               border-end-width="0.02in"
               border-start-width="0.02in"
               border-end-style="solid" 
               border-start-style="solid" 
               border-after-style="solid" 
               border-before-style="solid"
               padding-before="0.02in"
               padding-after="0.02in"
               padding-start="0.02in"
               padding-end="0.02in"
               background-color="red">
               This text has a "keep-with-previous" condition (within page) and therefore should also appear on the first page.             </fo:block>
        </fo:flow>
    </fo:page-sequence>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">        
              <fo:block
               text-align="center"
               border-before-width="0.02in"                
               border-after-width="0.02in"
               border-end-width="0.02in"
               border-start-width="0.02in"
               border-end-style="solid" 
               border-start-style="solid" 
               border-after-style="solid" 
               border-before-style="solid"
               padding-before="0.02in"
               padding-after="0.02in"
               padding-start="0.02in"
               padding-end="0.02in"
               background-color="red">
               This text should appear on page number two.
             </fo:block>                                            
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
