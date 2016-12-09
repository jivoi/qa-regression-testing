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
            margin-top="1.0in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.1in"
               margin-right="1.0in"
               margin-bottom="1.0in"/>
            </fo:simple-page-master>
    </fo:layout-master-set>
    <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
                <fo:block
                    border-before-width="0.5in"                
                    border-after-width="0.5in"
                    border-end-width="0.5in"
                    border-start-width="0.5in"
                    border-start-color="blue"
                    border-before-color="blue"
                    border-end-color="blue"
                    border-after-color="blue"
                    border-end-style="solid" 
                    border-start-style="solid" 
                    border-after-style="solid" 
                    border-before-style="solid"
                    padding-before="0.5in"
                    padding-after="0.5in"
                    padding-start="0.5in"
                    padding-end="0.5in"
                    text-align="center"
                    background-color="red">Content-rectangle
                  </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>

