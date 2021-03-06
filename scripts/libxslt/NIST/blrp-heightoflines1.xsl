<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

 <xsl:output indent="yes"/>
   
 <xsl:template match = "TEST">
   <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format"> 
    <fo:layout-master-set>
      <fo:simple-page-master 
        master-name = "test-page-master"
        page-width = "8.5in" page-height = "11in">
        <fo:region-body margin-top = "0.4in"/>
        <fo:region-before extent = "0.3in"/> 
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">
      <fo:flow flow-name="xsl-region-body">
        <xsl:apply-templates select="*"/>
      </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>

 <xsl:template match="IMG"> 
    <fo:external-graphic
           content-width="200px"
           content-height="200px"
           src="{@SRC}">
    </fo:external-graphic>
 </xsl:template>
 <xsl:template match="PARAGRAPH"> 
    <fo:block font-size="14px"
              line-height="30px">
      <xsl:apply-templates/>  
    </fo:block>
 </xsl:template>
</xsl:stylesheet>
