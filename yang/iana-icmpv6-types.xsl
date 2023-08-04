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

  <template match="iana:registry[@id='icmpv6-parameters-2']">
    <element name="yin:typedef">
      <attribute name="name">icmpv6-type-name</attribute>
      <element name="yin:type">
	<attribute name="name">enumeration</attribute>
	<apply-templates
	    select="iana:record[not(iana:name = 'Unassigned' or
		    starts-with(iana:name, 'Reserved') or 
                    starts-with(iana:name, 'Private'))]"/>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This enumeration type defines mnemonic names and
	  corresponding numeric values of ICMPv6 types.
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
      <attribute name="name">icmpv6-type</attribute>
      <element name="yin:type">
	<attribute name="name">union</attribute>
	<element name="yin:type">
	  <attribute name="name">uint8</attribute>
	</element>
	<element name="yin:type">
	  <attribute name="name">icmpv6-type-name</attribute>
	</element>
      </element>
      <element name="yin:description">
	<element name="yin:text">
          This type allows reference to an ICMPv6 type using either
          the assigned mnemonic name or numeric value.
	</element>
      </element>
    </element>
  </template>

  <template match="iana:record">
    <call-template name="enum">
      <with-param name="id">
	<choose>
	  <when test="contains(iana:name, '(Deprecated)')">
	    <value-of select="translate(normalize-space(substring-before(iana:name, 
                  '(Deprecated)')),' ','')"/>
	  </when>
	  <otherwise>
	    <value-of select="translate(normalize-space(iana:name),' ','')"/>
	  </otherwise>
	</choose>
      </with-param>
      <with-param name="description">
	<value-of select="concat(iana:name, '.')"/>
      </with-param>
      <with-param name="deprecated"
		  select="contains(iana:name, '(Deprecated)')"/>
    </call-template>
  </template>

</stylesheet>
