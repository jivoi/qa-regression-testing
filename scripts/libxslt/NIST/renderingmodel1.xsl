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
        page-width = "8.5in" 
        page-height = "11in"
        margin-left="1.0in"
        margin-top="1.0in"
        margin-right="1.0in"
        margin-bottom="1.0in">
        <fo:region-body
          margin-top = "1.0in"
          margin-left="1.0in"
          margin-right="3.0in"
          margin-bottom="1.0in"/> 
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">

      <fo:flow flow-name="xsl-region-body">
        <xsl:apply-templates select= "*"/>
      </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>

 <xsl:template match="block1"> 
       <fo:block background-color="red"><xsl:value-of select = "."/></fo:block>             
 </xsl:template>
 <xsl:template match="block2"> 
       <fo:block background-color="green"><xsl:value-of select = "."/></fo:block>
 </xsl:template>
 <xsl:template match="block3"> 
       <fo:block background-color="blue"><xsl:value-of select = "."/></fo:block>
 </xsl:template>
</xsl:stylesheet>
