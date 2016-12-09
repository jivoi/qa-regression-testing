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
        margin-right="1.0in"
        margin-left="1.0in"
        margin-top="1.0in"
        margin-bottom="1.0in">
        <fo:region-body
          margin-top = "1.0in"
          margin-left="1.0in"
          margin-right="1.0in"
          margin-bottom="1.0in"/>        
     </fo:simple-page-master>
    </fo:layout-master-set>

    <fo:page-sequence master-name="test-page-master">
      <fo:flow flow-name="xsl-region-body">
          <fo:block
           border-before-width="1.0in"
           border-before-style="solid"
           border-after-style="solid"
           border-after-width="1.0in"
           border-start-style="solid"
           border-start-width="1.0in"          
           border-end-style="solid"
           border-end-width="1.0in"></fo:block> 
      </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
