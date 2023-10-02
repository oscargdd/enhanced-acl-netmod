<?xml version="1.0" encoding="utf-8"?>
<stylesheet
    xmlns="http://www.w3.org/1999/XSL/Transform"
    xmlns:html="http://www.w3.org/1999/xhtml"
    xmlns:iana="http://www.iana.org/assignments"
    xmlns:yin="urn:ietf:params:xml:ns:yang:yin:1"
    version="1.0">
  <import href="../../../xslt/iana-yinx.xsl"/>
  <output method="xml" encoding="utf-8"/>
  <strip-space elements="*"/>

  <template match="iana:registry[@id='extension-header']">
    <element name="yin:typedef">
      <attribute name="name">ipv6-extension-header-type-name</attribute>
      <element name="yin:type">
	<attribute name="name">enumeration</attribute>
	<apply-templates
	    select="iana:record[not(iana:description = 'Unassigned' or
		    starts-with(iana:description, 'Reserved') or 
                    starts-with(iana:description, 'Use for experimentation and testing')) or 
                    contains(iana:description, 'experimental')]"/>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This enumeration type defines mnemonic names and
	  corresponding numeric values of IPv6 Extension header types.
	</element>
      </element>
      <element name="yin:reference">
	<element name="yin:text">
          RFC 2708: IANA Allocation Guidelines For Values In
                    the Internet Protocol and Related Headers
	</element>
      </element>
    </element>
    <element name="yin:typedef">
      <attribute name="name">ipv6-extension-header-type</attribute>
      <element name="yin:type">
	<attribute name="name">union</attribute>
	<element name="yin:type">
	  <attribute name="name">uint8</attribute>
	</element>
	<element name="yin:type">
	  <attribute name="name">ipv6-extension-header-type-name</attribute>
	</element>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This type allows reference to an IPv6 Extension header type using either
          the assigned mnemonic name or the numeric protocol number value.
	</element>
      </element>
    </element>
  </template>

  <template match="iana:record">
    <call-template name="enum">
      <with-param name="id">
	<choose>
	  <when test="contains(iana:description, '(Deprecated)')">
	    <value-of select="translate(normalize-space(substring-before(iana:description, 
                  '(Deprecated)')),' ','')"/>
	  </when>
	  <otherwise>
	    <value-of select="translate(normalize-space(iana:description),' ','')"/>
	  </otherwise>
	</choose>
      </with-param>
      <with-param name="deprecated"
		  select="contains(iana:description, '(Deprecated)')"/>
    </call-template>
  </template>

</stylesheet>
