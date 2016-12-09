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
    <fo:block background-color="gray">
      <xsl:apply-templates/>
    </fo:block>
 </xsl:template>

<xsl:template match="SPAN"> 
    <fo:inline border-left-style="solid" border-left-color="purple"
               border-bottom-style="solid" border-bottom-color="purple"
               border-top-style="solid" border-top-color="purple"
               border-right-style="solid" border-right-color="purple">
      <xsl:apply-templates/>
    </fo:inline>
 </xsl:template>
</xsl:stylesheet>