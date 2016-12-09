<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

 <xsl:output indent="yes"/>

 <xsl:attribute-set name="properties">
   <xsl:attribute name="border-left-color">purple</xsl:attribute>
   <xsl:attribute name="border-left-style">groove</xsl:attribute>
   <xsl:attribute name="border-left-width">thick</xsl:attribute>
   <xsl:attribute name="border-bottom-color">purple</xsl:attribute>
   <xsl:attribute name="border-bottom-style">double</xsl:attribute>
   <xsl:attribute name="border-bottom-width">thick</xsl:attribute>
   <xsl:attribute name="border-top-color">purple</xsl:attribute>
   <xsl:attribute name="border-top-style">double</xsl:attribute>
   <xsl:attribute name="border-top-width">thick</xsl:attribute>
   <xsl:attribute name="border-right-color">purple</xsl:attribute>
   <xsl:attribute name="border-right-style">groove</xsl:attribute>
   <xsl:attribute name="border-right-width">thick</xsl:attribute>
 </xsl:attribute-set>
   
 <xsl:template match = "TEST">
   <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format"> 
    <fo:layout-master-set>
      <fo:simple-page-master 
        master-name = "test-page-master"
        page-width = "8.5in" page-height = "11in">
        <fo:region-body margin-top = "0.4in"/> 
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">
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