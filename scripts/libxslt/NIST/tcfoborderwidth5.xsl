<?xml version="1.0" encoding="UTF-8"?>

   
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format" 
                version="1.0">

<xsl:output indent="yes"/>
 
<xsl:attribute-set name = "foProperties1">
  <xsl:attribute name = "column-width">2.0in</xsl:attribute>
</xsl:attribute-set>

<xsl:attribute-set name = "foProperties4">
  <xsl:attribute name = "background-color">red</xsl:attribute>
  <xsl:attribute name = "border-before-width">thick</xsl:attribute>
  <xsl:attribute name = "border-after-width">thick</xsl:attribute>
  <xsl:attribute name = "border-start-width">thick</xsl:attribute>
  <xsl:attribute name = "border-end-width">thick</xsl:attribute>
  <xsl:attribute name = "border-before-style">none</xsl:attribute>
  <xsl:attribute name = "border-after-style">none</xsl:attribute>
  <xsl:attribute name = "border-start-style">solid</xsl:attribute>
  <xsl:attribute name = "border-end-style">solid</xsl:attribute>
</xsl:attribute-set>
   
 <xsl:template match = "testcase">
   <fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
     <fo:layout-master-set>
       <fo:simple-page-master
            page-height="11in" 
            page-width="8.5in"
            margin-left="1.0in"
            margin-top="0.2in"
            margin-bottom="1.0in"
            margin-right="1.0in"
            master-name="test-page-master">
            <fo:region-body
               margin-left="1.0in"
               margin-top="0.2in"
               margin-right="1.0in"
               margin-bottom="1.0in"/>
       </fo:simple-page-master>
     </fo:layout-master-set>
     <fo:page-sequence master-name="test-page-master">
        <fo:flow flow-name="xsl-region-body">
           <fo:table>
             <fo:table-column xsl:use-attribute-sets = "foProperties1">
             </fo:table-column>
             <fo:table-body>
              <fo:table-row>
               <fo:table-cell xsl:use-attribute-sets = "foProperties4">
                <fo:block>
                 <xsl:value-of select = "/descendant::fo[position()=5]/foText"/>
                </fo:block>
               </fo:table-cell>
              </fo:table-row>
             </fo:table-body>
           </fo:table>
   
        </fo:flow>
     </fo:page-sequence>
   </fo:root>
 </xsl:template>
</xsl:stylesheet>
 
