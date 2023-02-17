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

  <template match="iana:registry[@id='icmp-parameters-types']">
    <element name="yin:typedef">
      <attribute name="name">icmp-type-name</attribute>
      <element name="yin:type">
	<attribute name="name">enumeration</attribute>
	<apply-templates
	    select="iana:record[not(iana:description = 'Unassigned' or
		    starts-with(iana:description, 'Reserved') or 
                    starts-with(iana:description, 'RFC3692')) or 
                    contains(iana:description, 'experimental')]"/>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This enumeration type defines mnemonic names and
	  corresponding numeric values of ICMP types.
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
      <attribute name="name">icmp-type</attribute>
      <element name="yin:type">
	<attribute name="name">union</attribute>
	<element name="yin:type">
	  <attribute name="name">uint8/</attribute>
	</element>
	<element name="yin:type">
	  <attribute name="name">icmp-type-name</attribute>
	</element>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This type allows reference to an ICMP type using either
          the assigned mnemonic name or numeric value.
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
