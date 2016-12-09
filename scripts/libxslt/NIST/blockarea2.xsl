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
            margin-top="0.2in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.0in"
               margin-right="3.0in"
               margin-bottom="1.0in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
           <fo:block
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.02in"
              padding-after="0.02in"
              padding-start="0.02in"
              padding-end="0.02in"
              background-color="black">
            </fo:block>
            <fo:block space-before.optimum="0.1in"
              space-before.precedence="force"
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.2in"
              padding-after="0.2in"
              padding-start="0.2in"
              padding-end="0.2in"
              background-color="red">Space before this area should be 0.1 inches
           </fo:block>
           <fo:block space-before.optimum="0.2in"
              space-before.precedence="force"
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.2in"
              padding-after="0.2in"
              padding-start="0.2in"
              padding-end="0.2in"
              background-color="red">Space before this area should be 0.2 inches
           </fo:block>
           <fo:block space-before="0.3in"
              space-before.precedence="force"
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.2in"
              padding-after="0.2in"
              padding-start="0.2in"
              padding-end="0.2in"
              background-color="red">Space before this area should be 0.3 inches
           </fo:block>
           <fo:block space-before.optimum="0.4in"
              space-before.precedence="force"
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.2in"
              padding-after="0.2in"
              padding-start="0.2in"
              padding-end="0.2in"
              background-color="red">Space before this area should be 0.4 inches
           </fo:block>
           <fo:block space-before.optimum="0.5in"
              space-before.precedence="force"
              border-before-width="0.01in"                
              border-after-width="0.01in"
              border-end-width="0.01in"
              border-start-width="0.01in"
              border-end-style="solid" 
              border-start-style="solid" 
              border-after-style="solid" 
              border-before-style="solid"
              padding-before="0.2in"
              padding-after="0.2in"
              padding-start="0.2in"
              padding-end="0.2in"
              background-color="red">Space before this area should be 0.5 inches
           </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
