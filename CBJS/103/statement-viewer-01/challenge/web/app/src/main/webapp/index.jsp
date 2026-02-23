<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FinSight - Financial Statement Viewer</title>
    <link rel="stylesheet" href="<%=request.getContextPath()%>/assets/css/main.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="icon"
        href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>F</text></svg>">
    <meta name="description" content="Secure financial statement viewing and management platform">
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
                </div>
            </div>
        </header>

        <!-- Hero Section -->
        <main class="main-content">
            <div class="container">
                <!-- Hero -->
                <section class="text-center mb-5" style="padding: 4rem 0;">
                    <div style="max-width: 800px; margin: 0 auto;">
                        <h1
                            style="font-size: 3.5rem; font-weight: 700; margin-bottom: 1.5rem; background: linear-gradient(135deg, var(--primary-blue) 0%, var(--success) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
                            FinSight
                        </h1>
                        <h2
                            style="font-size: 1.5rem; color: var(--text-secondary); margin-bottom: 2rem; font-weight: 400;">
                            Secure Financial Statement Management
                        </h2>
                        <p
                            style="font-size: 1.125rem; color: var(--text-muted); margin-bottom: 3rem; line-height: 1.8;">
                            A modern, secure platform for viewing, uploading, and managing your financial documents.
                            Built with enterprise-grade security and user experience in mind.
                        </p>

                        <!-- Quick Access Form -->
                        <div class="card" style="max-width: 500px; margin: 0 auto; text-align: left;" id="get-started">
                            <div class="card-header">
                                <h3 class="card-title">Quick Access</h3>
                                <p class="card-subtitle">Enter your User ID to access your statements</p>
                            </div>

                            <form id="accessForm" action="statements/view" method="get">
                                <div class="form-group">
                                    <label for="userId" class="form-label">
                                        User ID
                                    </label>
                                    <input type="text" id="userId" name="userId" class="form-control"
                                        placeholder="Enter your 32-character User ID" pattern="[a-f0-9]{32}"
                                        maxlength="32" value="2460d5ca8a01fa885703e5cb32644b24" required>
                                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">
                                        Your User ID is a 32-character hexadecimal string
                                    </div>
                                </div>

                                <div class="d-flex gap-3">
                                    <button type="submit" class="btn btn-primary btn-lg" style="flex: 1;">
                                        View Statements
                                    </button>
                                    <button type="button" onclick="handleUploadClick(this)" class="btn btn-outline btn-lg"
                                        style="flex: 1;">
                                        Upload
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </section>
            </div>
        </main>
    </div>

    <!-- Scripts -->
    <script src="assets/js/main.js"></script>
</body>

</html>