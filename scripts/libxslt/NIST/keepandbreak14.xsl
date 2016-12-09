<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

<xsl:output indent="yes"/>

<xsl:template match = "TEST">
 <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
    <fo:layout-master-set>
        <fo:simple-page-master
            page-height="11.0in" 
            page-width="8.5in"
            margin-left="1.0in"
            margin-top="1.0in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.2in"
               margin-right="1.0in"
               margin-bottom="1.0in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
            <fo:block text-align="center"
              border-before-width="0.02in"                
              border-after-width="0.02in"
              border-end-width="0.02in"
              border-start-width="0.02in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.07in"
              padding-after="0.07in"
              padding-start="0.07in"
              padding-end="0.07in"
              background-color="white">
              This is a parent area P with three descendants.
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
               This is a the first descendant area in P.
             </fo:block>
             <fo:block
               text-align="center"
               space-before.optimum ="0.07in"
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
               This is another descendant area in P.
              </fo:block>
             <fo:block
               text-align="center"
               space-before.optimum ="0.07in"
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
               This is a trailing area in P (there should be no areas other than P following this area)
              </fo:block>
           </fo:block>                                                            
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
