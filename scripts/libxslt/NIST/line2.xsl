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
            margin-top="0.5in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.1in"
               margin-right="2.0in"
               margin-bottom="1.0in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
           <fo:block space-after.optimum="0.1in" line-stacking-strategy="line-height" line-height="0.5in" background-color="red">The allocation rectangle of a line area is determined by the 'line-stacking-strategy" trait.  This tests sets that trait to 'line-height', which is set to "0.5in".
           </fo:block>
          <fo:block line-stacking-strategy="line-height" line-height="0.25in" background-color="aqua">This area sets the line height to "0.25in", therefore the allocation rectangle of the lines on the blue area should be smaller than the lines on the red area.
           </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
