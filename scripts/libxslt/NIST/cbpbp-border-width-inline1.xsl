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
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">
      <fo:flow flow-name="xsl-region-body">
        <xsl:apply-templates select= "*"/>
      </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>

 <xsl:template match="PARAGRAPH"> 
    <fo:block border-left-width="25px" border-left-style="solid"
              border-top-width="25px" border-top-style="solid"
              border-bottom-width="25px" border-bottom-style="solid"
              border-right-width="25px" border-right-style="solid" >
      <xsl:apply-templates/>
    </fo:block>
 </xsl:template>

<xsl:template match="SPAN"> 
    <fo:inline border-left-width="thin" border-left-style="solid"
               border-bottom-width="thin" border-bottom-style="solid"
               border-top-width="thin" border-top-style="solid" 
               border-right-width="thin" border-right-style="solid">
      <xsl:apply-templates/>
    </fo:inline>
 </xsl:template>
</xsl:stylesheet>
