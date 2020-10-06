<%--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
--%>
<%@ page contentType="text/html" pageEncoding="UTF-8" session="false" %>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
    <%
    // Sanitize the contextPath to ensure it is on this server
    // rather than getting it from the header directly
    String contextPath = request.getAttribute("contextPath").toString();
%>
<html>
    <head>
        <title><%= request.getAttribute("title") == null ? "" : org.apache.nifi.util.EscapeUtils.escapeHtml(request.getAttribute("title").toString()) %></title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <link rel="shortcut icon" href="<%= contextPath %>/images/nifi16.ico"/>
        <link rel="stylesheet" href="js/jquery/modal/jquery.modal.css?${project.version}" type="text/css" />
        <link rel="stylesheet" href="assets/qtip2/dist/jquery.qtip.min.css?" type="text/css" />
        <link rel="stylesheet" href="assets/jquery-ui-dist/jquery-ui.min.css" type="text/css" />
<%--        <link rel="stylesheet" href="assets/angular-material/angular-material.min.css" type="text/css" />--%>
        <link rel="stylesheet" href="<%= contextPath %>/nifi/assets/reset.css/reset.css" type="text/css" />
        <link rel="stylesheet" href="<%= contextPath %>/nifi/css/common-ui.css" type="text/css" />
        <script type="text/javascript" src="assets/jquery/dist/jquery.min.js"></script>
        <script type="text/javascript" src="js/jquery/jquery.base64.js"></script>
        <script type="text/javascript" src="js/jquery/jquery.count.js"></script>
        <script type="text/javascript" src="js/jquery/jquery.center.js"></script>
        <script type="text/javascript" src="js/jquery/modal/jquery.modal.js?${project.version}"></script>
        <script type="text/javascript" src="assets/qtip2/dist/jquery.qtip.min.js"></script>
        <script type="text/javascript" src="assets/jquery-ui-dist/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/nf/nf-namespace.js?${project.version}"></script>
        <script type="text/javascript" src="assets/lodash-core/distrib/lodash-core.min.js"></script>

        <style type="text/css">
            #logout-contents-container {
                position: absolute;
                top: 0;
                left: 0;
                bottom: 0;
                right: 0;
                background: #fff url(<%= contextPath %>/nifi/images/bg-error.png) left top no-repeat;
                padding-top: 100px;
                padding-left: 100px;
            }

            #logout-message-title {
                font-size: 18px;
                color: #294c58;
                margin-bottom: 16px;
            }

            #logout-message {
                font-size: 11px;
            }

            #logout-user-links-container {
                position: absolute;
                top: 0;
                left: 0;
                padding-top: 100px;
                padding-left: 100px;
                z-index: 1300;
                width: 412px;
            }

            #logout-user-links {
                float: right;
            }
        </style>

        <script type="text/javascript">
            $(document).ready(function () {
                $('#user-home').on('mouseenter', function () {
                    $(this).addClass('link-over');
                }).on('mouseleave', function () {
                    $(this).removeClass('link-over');
                }).on('click', function () {
                    window.location = '<%= contextPath %>/nifi';
                });
            });
        </script>
    </head>

    <body class="logout-body">
    <div id="logout-user-links-container">
        <ul id="logout-user-links" class="links">
            <li>
                <span id="user-home" class="link">home</span>
            </li>
        </ul>
    </div>
        <div id="logout-contents-container">
            <jsp:include page="/WEB-INF/partials/logout/logout-message.jsp"/>
        </div>
    </body>
</html>