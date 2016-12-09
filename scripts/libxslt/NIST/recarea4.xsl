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
            margin-top="0.1in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="0.1in"
               margin-top="0.1in"
               margin-right="3.0in"
               margin-bottom="7.0in">
            </fo:region-body>
           </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
               <fo:block-container writing-mode="rl-tb">
                <fo:block
                    space-after.optimum = "0.1in"
                    space-after.maximum = "0.1in"
                    padding-before="0.3in"
                    padding-after="0.3in"
                    padding-start="0.3in"
                    padding-end="0.3in"><fo:bidi-override unicode-bidi="bidi-override">
                    THIS TEXT SHOULD BE BACKWARDS.</fo:bidi-override>
                 </fo:block>
               </fo:block-container>
                  <fo:block
                    space-after.optimum = "0.1in"
                    space-after.maximum = "0.1in"
                    padding-before="0.3in"
                    padding-after="0.3in"
                    padding-start="0.3in"
                    padding-end="0.3in">
                    BUT THIS ONE SHOULD BE NORMAL.
                  </fo:block>
         </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
