<%@ taglib uri="/bbUI" prefix="bbUI"%>
<%@ page import="java.io.*" %>

<bbUI:docTemplate title="Error">

<% String iconUrl = "/images/ci/icons/x_ia.gif"; %>
<bbUI:titleBar iconUrl="<%=iconUrl%>">
<%= request.getAttribute("gxMessage") %>
</bbUI:titleBar>

</bbUI:docTemplate>
