<%@ page contentType="text/html;chars                        <div class="empty-state-icon" style="font-size: 6rem;">!</div>
                        <h1 style="color: var(--error); margin-bottom: 1rem;">Oops! Something went wrong</h1>=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - FinSight</title>
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
                    <a href="<%=request.getContextPath()%>" class="logo">
                        <div class="logo-icon">F</div>
                        FinSight
                    </a>
                    <nav class="header-nav">
                        <a href="<%=request.getContextPath()%>" class="nav-link">Home</a>
                        <a href="javascript:history.back()" class="nav-link">← Back</a>
                    </nav>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="main-content">
            <div class="container">
                <div class="card text-center" style="max-width: 600px; margin: 2rem auto;">
                    <div class="empty-state">
                        <div class="empty-state-icon" style="font-size: 6rem;">ERROR</div>
                        <h1 style="color: var(--error); margin-bottom: 1rem;">Oops! Something went wrong</h1>
                        
                        <% 
                        String errorMessage = "An unexpected error occurred";
                        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
                        String requestUri = (String) request.getAttribute("javax.servlet.error.request_uri");
                        Throwable exception = (Throwable) request.getAttribute("javax.servlet.error.exception");
                        
                        if (statusCode != null) {
                            switch (statusCode) {
                                case 400:
                                    errorMessage = "Bad Request - The request could not be understood";
                                    break;
                                case 401:
                                    errorMessage = "Unauthorized - Authentication required";
                                    break;
                                case 403:
                                    errorMessage = "Forbidden - Access denied";
                                    break;
                                case 404:
                                    errorMessage = "Page Not Found - The requested resource was not found";
                                    break;
                                case 405:
                                    errorMessage = "Method Not Allowed - The request method is not supported";
                                    break;
                                case 500:
                                    errorMessage = "Internal Server Error - Something went wrong on our end";
                                    break;
                                default:
                                    errorMessage = "Error " + statusCode + " - " + errorMessage;
                            }
                        }
                        %>
                        
                        <div class="alert alert-error" style="text-align: left; margin: 2rem 0;">
                            <strong>Error Details:</strong><br>
                            <%= errorMessage %>
                            
                            <% if (requestUri != null) { %>
                                <br><strong>Requested URL:</strong> <%= requestUri %>
                            <% } %>
                            
                            <% if (statusCode != null) { %>
                                <br><strong>Status Code:</strong> <%= statusCode %>
                            <% } %>
                        </div>

                        <% if (exception != null && "development".equals(System.getProperty("app.mode"))) { %>
                            <div class="alert alert-warning" style="text-align: left; margin: 1rem 0;">
                                <strong>Technical Details:</strong><br>
                                <code style="font-size: 0.8rem;">
                                    <%= exception.getClass().getSimpleName() %>: <%= exception.getMessage() %>
                                </code>
                            </div>
                        <% } %>

                        <div class="d-flex gap-3 justify-center mt-4">
                            <button onclick="history.back()" class="btn btn-secondary">
                                Go Back
                            </button>
                            
                            <a href="<%=request.getContextPath()%>/" class="btn btn-primary">
                                Go Home
                            </a>
                            
                            <button onclick="window.location.reload()" class="btn btn-outline">
                                Retry
                            </button>
                        </div>

                        <div style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid var(--border-primary);">
                            <h4 style="color: var(--text-primary); margin-bottom: 1rem;">Common Solutions</h4>
                            <div style="text-align: left; max-width: 400px; margin: 0 auto;">
                                <ul style="color: var(--text-secondary); line-height: 1.8;">
                                    <li>Check if the URL is correct</li>
                                    <li>Try refreshing the page</li>
                                    <li>Verify your User ID is valid</li>
                                    <li>Ensure the file exists</li>
                                    <li>Check your internet connection</li>
                                </ul>
                            </div>
                        </div>

                        <div style="margin-top: 2rem; font-size: 0.875rem; color: var(--text-muted);">
                            If the problem persists, please contact our support team.
                            <br>
                            <strong>Error ID:</strong> <code><%= System.currentTimeMillis() %></code>
                        </div>
                    </div>
                </div>

                <!-- Help Card -->
                <div class="card" style="max-width: 800px; margin: 2rem auto;">
                    <div class="card-header">
                        <h3 class="card-title">💡 Need More Help?</h3>
                    </div>
                    
                    <div class="d-flex gap-4">
                        <div style="flex: 1;">
                            <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">File Access Issues</h4>
                            <p style="color: var(--text-secondary); font-size: 0.875rem;">
                                Make sure you have the correct User ID and the file you're trying to access exists.
                            </p>
                        </div>
                        <div style="flex: 1;">
                            <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">Upload Problems</h4>
                            <p style="color: var(--text-secondary); font-size: 0.875rem;">
                                Check file size (max 10MB) and format (PDF/TXT only).
                            </p>
                        </div>
                        <div style="flex: 1;">
                            <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">System Errors</h4>
                            <p style="color: var(--text-secondary); font-size: 0.875rem;">
                                Server issues are usually temporary. Try again in a few minutes.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Scripts -->
    <script src="<%=request.getContextPath()%>/assets/js/main.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-hide technical details after 10 seconds if not in development
            const technicalDetails = document.querySelector('.alert-warning');
            if (technicalDetails && !'development'.includes('<%= System.getProperty("app.mode", "production") %>')) {
                setTimeout(() => {
                    technicalDetails.style.opacity = '0.5';
                }, 10000);
            }
            
            // Track error for analytics (in production)
            if (typeof gtag !== 'undefined') {
                gtag('event', 'exception', {
                    'description': '<%= errorMessage.replaceAll("'", "\\\\'") %>',
                    'fatal': false
                });
            }
        });
    </script>
</body>
</html>
