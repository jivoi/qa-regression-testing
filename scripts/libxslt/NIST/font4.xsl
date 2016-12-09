<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

 <xsl:output indent="yes"/>

 <xsl:attribute-set name="properties">
   <xsl:attribute name="font">
     <xsl:if test="position() = 1">150%/150% sans-serif</xsl:if>
   </xsl:attribute>
 </xsl:attribute-set>
   
 <xsl:template match = "TEST">
   <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format"> 
    <fo:layout-master-set>
      <fo:simple-page-master 
        master-name = "test-page-master"
        page-width = "8.5in" page-height = "11in">
        <fo:region-before extent = "0.3in"/>
        <fo:region-body margin-top = "0.4in"/>         
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">
      <fo:static-content flow-name="xsl-region-before">
        <fo:block text-align = "center"> 
           The XSL Formatting Objects Test Suite Version 1.0 
        </fo:block>
      </fo:static-content> 

      <fo:flow flow-name="xsl-region-body">
        <xsl:apply-templates select="//PARAGRAPH"/>
      </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>

 <xsl:template match="PARAGRAPH"> 
    <fo:block xsl:use-attribute-sets="properties">
          <xsl:value-of select="."/>
    </fo:block>
 </xsl:template>
</xsl:stylesheet>
