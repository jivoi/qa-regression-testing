<?xml version="1.0" encoding="ISO-8859-15"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output encoding="ISO-8859-15"/>

<xsl:template match="br">
  <br/>
</xsl:template>

<xsl:template match="a">
  <a href="{@href}"><xsl:apply-templates/></a>
</xsl:template>

<xsl:template match="article">
<h3><xsl:value-of select="title"/></h3>
<u>Ingredients:</u> <xsl:value-of select="ingredients"/>
<br/>
<u>Procedure:</u> <xsl:apply-templates select="body"/>
</xsl:template>

<xsl:template match="main">
  <html>
  <head>
  <title>recipes</title>
  </head>
  <body bgcolor="#ffffff">
  <h2>Our best recipes "à la française"</h2>
  <xsl:apply-templates select="article"/>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
