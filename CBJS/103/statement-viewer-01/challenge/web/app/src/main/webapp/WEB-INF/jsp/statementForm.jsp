<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statement Viewer - FinSight</title>
    <link rel="stylesheet" href="<%=request.getContextPath()%>/assets/css/main.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>F</text></svg>">
</head>
<body class="fade-in">
    <div class="main-wrapper">
        <!-- Header -->
        <header class="header">
            <div class="container">
                <div class="header-content">
                    <a href="<%=request.getContextPath()%>/" class="logo">
                        <div class="logo-icon">F</div>
                        FinSight
                    </a>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="main-content">
            <div class="container">
                <!-- Statements Table -->
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex justify-between align-center">
                            <div>
                                <h3 class="card-title">Your Statements</h3>
                                <p class="card-subtitle">
                                    <c:choose>
                                        <c:when test="${not empty statements}">
                                            ${statements.size()} statement(s) found
                                        </c:when>
                                        <c:otherwise>
                                            No statements available
                                        </c:otherwise>
                                    </c:choose>
                                </p>
                            </div>
                            <div>
                                <a href="<%=request.getContextPath()%>/statements/upload?userId=${userId}" 
                                   class="btn btn-primary">
                                    Upload New Statement
                                </a>
                            </div>
                        </div>
                    </div>

                    <c:choose>
                        <c:when test="${not empty statements}">
                            <div class="table-container">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Document</th>
                                            <th>Type</th>
                                            <th>File Path</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <c:forEach var="statement" items="${statements}" varStatus="status">
                                            <tr class="slide-up">
                                                <td>
                                                    <div class="d-flex align-center gap-2">
                                                        <div>
                                                            <div style="font-weight: 600; color: var(--text-primary);">
                                                                ${statement.fileName}
                                                            </div>
                                                            <div style="font-size: 0.75rem; color: var(--text-muted);">
                                                                Statement #${status.index + 1}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td>
                                                    <div class="badge badge-success">
                                                        <c:choose>
                                                            <c:when test="${statement.filePath.endsWith('.pdf')}">pdf</c:when>
                                                            <c:when test="${statement.filePath.endsWith('.txt')}">txt</c:when>
                                                            <c:otherwise>FILE</c:otherwise>
                                                        </c:choose>
                                                    </div>
                                                </td>
                                                <td>
                                                    <code style="background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; color: var(--text-secondary);">
                                                        <c:set var="pathArray" value="${fn:split(statement.filePath, '/')}" />
                                                        <c:out value="${pathArray[1]}" />
                                                    </code>
                                                </td>
                                                <td>
                                                    <div class="d-flex gap-2">
                                                        <a href="<%=request.getContextPath()%>/statements/download?file=${statement.filePath}" 
                                                           class="btn btn-sm btn-primary btn-download" 
                                                           data-file="${statement.filePath}"
                                                           target="_blank">
                                                            Download
                                                        </a>
                                                    </div>
                                                </td>
                                            </tr>
                                        </c:forEach>
                                    </tbody>
                                </table>
                            </div>

                            <!-- Statistics -->
                            <div class="mt-4" style="padding: 1rem; background: var(--bg-secondary); border-radius: 8px;">
                                <div class="d-flex justify-between align-center">
                                    <div>
                                        <strong style="color: var(--text-primary);">Total Documents:</strong>
                                        <span class="badge badge-info ml-2">${statements.size()}</span>
                                    </div>
                                </div>
                            </div>
                        </c:when>
                        <c:otherwise>
                            <div class="empty-state">
                                <div class="empty-state-icon">EMPTY</div>
                                <h3>No Statements Found</h3>
                                <p>You don't have any financial statements yet.</p>
                                <div class="mt-4">
                                    <a href="<%=request.getContextPath()%>/statements/upload?userId=${userId}" 
                                       class="btn btn-primary">
                                        Upload Your First Statement
                                    </a>
                                </div>
                            </div>
                        </c:otherwise>
                    </c:choose>
                </div>
            </div>
        </main>
    </div>

    <!-- Scripts -->
    <script src="<%=request.getContextPath()%>/assets/js/main.js"></script>
</body>
</html>
