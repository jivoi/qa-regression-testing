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
                    text-align="start"><xsl:value-of select="block1"/>
                   <fo:block
                     border-before-width="0.3in"                
                     border-after-width="0.3in"
                     border-end-width="0.3in"
                     border-start-width="0.3in"
                     border-start-color="red"
                     border-before-color="red"
                     border-end-color="red"
                     border-after-color="red"
                     border-end-style="solid" 
                     border-start-style="solid" 
                     border-after-style="solid" 
                     border-before-style="solid"
                     padding-before="0.3in"
                     padding-after="0.3in"
                     padding-start="0.3in"
                     padding-end="0.3in"
                     text-align="start"><xsl:value-of select="block2"/>
                     <fo:block
                       border-before-width="0.1in"                
                       border-after-width="0.1in"
                       border-end-width="0.1in"
                       border-start-width="0.1in"
                       border-start-color="aqua"
                       border-before-color="aqua"
                       border-end-color="aqua"
                       border-after-color="aqua"
                       border-end-style="solid" 
                       border-start-style="solid" 
                       border-after-style="solid" 
                       border-before-style="solid"
                       padding-before="0.1in"
                       padding-after="0.1in"
                       padding-start="0.1in"
                       padding-end="0.1in"
                       text-align="start"><xsl:value-of select="block3"/>
                     </fo:block>
                   </fo:block>
                </fo:block>
        </fo:flow>
    </fo:page-sequence>
  </fo:root>
 </xsl:template>
</xsl:stylesheet>
