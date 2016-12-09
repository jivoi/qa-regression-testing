<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

<xsl:output indent="yes"/>

<xsl:template match = "TEST">
 <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
    <fo:layout-master-set>
        <fo:simple-page-master
            page-height="2.0in" 
            page-width="2.0in"
            margin-left="0.1in"
            margin-top="0.1in"
            margin-bottom="0.1in"
            margin-right="0.1in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="0.1in"
               margin-top="0.1in"
               margin-right="0.1in"
               margin-bottom="0.1in"/>
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
               This is the page number 1
             </fo:block>                                            
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
               This is the page number 2
             </fo:block>                                            
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
               This is the page number 3
             </fo:block>                                            
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
