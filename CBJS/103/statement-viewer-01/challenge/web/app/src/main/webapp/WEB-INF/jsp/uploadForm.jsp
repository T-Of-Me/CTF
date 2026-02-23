<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Statement - FinSight</title>
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
                <!-- Upload Form -->
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex justify-between align-center">
                            <div>
                                <h3 class="card-title">Upload Document</h3>
                                <p class="card-subtitle">Choose a PDF or TXT file to upload (max 10MB)</p>
                            </div>
                            <div>
                                <a href="<%=request.getContextPath()%>/statements/view?userId=${userId}" 
                                   class="btn btn-outline">
                                    View Statements
                                </a>
                            </div>
                        </div>
                    </div>
                        <c:if test="${not empty message}">
                            <div class="alert alert-${messageType}">
                                <c:choose>
                                    <c:when test="${messageType eq 'success'}">SUCCESS:</c:when>
                                    <c:when test="${messageType eq 'error'}">ERROR:</c:when>
                                    <c:otherwise>INFO:</c:otherwise>
                                </c:choose>
                                ${message}
                            </div>
                        </c:if>

                    <form action="<%=request.getContextPath()%>/statements/upload" 
                          method="post" 
                          enctype="multipart/form-data" 
                          class="upload-form"
                          id="uploadForm">
                        
                        <input type="hidden" name="userId" value="${userId}" id="hiddenUserId" required>

                        <!-- File Upload Area -->
                        <div class="form-group">
                            <label class="form-label" for="file">
                                Select Financial Statement
                            </label>
                            <div class="file-upload">
                                <input type="file" 
                                       id="file" 
                                       name="file" 
                                       accept=".pdf,.txt" 
                                       required>
                                <div class="file-upload-label">
                                    <div class="file-upload-content">
                                        <div class="file-upload-icon">+</div>
                                        <div>
                                            <div style="font-weight: 600; margin-bottom: 4px;">Choose a file or drag it here</div>
                                            <div style="font-size: 0.75rem; color: var(--text-muted);">PDF or TXT files, up to 10MB</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">
                                Supported formats: PDF, TXT • Maximum size: 10MB
                            </div>
                        </div>

                        <!-- Upload Button -->
                        <div class="form-group">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <span class="btn-text">Upload Statement</span>
                                <span class="btn-loading" style="display: none;">
                                    <span class="loading"></span> Uploading...
                                </span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>

    <!-- Scripts -->
    <script src="<%=request.getContextPath()%>/assets/js/main.js"></script>
    <script src="<%=request.getContextPath()%>/assets/js/upload.js"></script>
</body>
</html>
