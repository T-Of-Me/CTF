/**
 * FinSight Statement Viewer - Main JavaScript
 * Modern Fintech Application
 */

class FinSightApp {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeComponents();
        this.setupFormValidation();
        this.setupFileUpload();
        this.setupTooltips();
        this.animateOnLoad();
    }

    setupEventListeners() {
        // Loading state management
        document.addEventListener('DOMContentLoaded', () => {
            this.hideLoader();
        });

        // Form submissions
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => {
                this.showLoader();
                this.validateForm(form, e);
            });
        });

        // Button interactions
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.handleButtonClick(e);
            });
        });

        // File input changes
        document.querySelectorAll('input[type="file"]').forEach(input => {
            input.addEventListener('change', (e) => {
                this.handleFileChange(e);
            });
        });

        // Search functionality
        const searchInput = document.querySelector('#searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.handleSearch(e.target.value);
            });
        }
    }

    initializeComponents() {
        // Initialize dropdowns
        this.initDropdowns();

        // Initialize modals
        this.initModals();

        // Initialize tables
        this.initTables();

        // Initialize charts if needed
        this.initCharts();
    }

    setupFormValidation() {
        document.querySelectorAll('.form-control').forEach(input => {
            input.addEventListener('blur', () => {
                this.validateField(input);
            });

            input.addEventListener('input', () => {
                this.clearFieldError(input);
            });
        });
    }

    setupFileUpload() {
        document.querySelectorAll('.file-upload').forEach(uploadArea => {
            const input = uploadArea.querySelector('input[type="file"]');
            const label = uploadArea.querySelector('.file-upload-label');

            if (!input || !label) return;

            // Drag and drop functionality
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, this.preventDefaults, false);
            });

            ['dragenter', 'dragover'].forEach(eventName => {
                uploadArea.addEventListener(eventName, () => {
                    uploadArea.classList.add('drag-over');
                }, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, () => {
                    uploadArea.classList.remove('drag-over');
                }, false);
            });

            uploadArea.addEventListener('drop', (e) => {
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    input.files = files;
                    this.handleFileChange({ target: input });
                }
            });
        });
    }

    setupTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target);
            });

            element.addEventListener('mouseleave', (e) => {
                this.hideTooltip(e.target);
            });
        });
    }

    animateOnLoad() {
        // Add fade-in animation to cards
        document.querySelectorAll('.card').forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';

            setTimeout(() => {
                card.style.transition = 'all 0.5s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });

        // Animate table rows
        document.querySelectorAll('.table tbody tr').forEach((row, index) => {
            row.style.opacity = '0';
            row.style.transform = 'translateX(-20px)';

            setTimeout(() => {
                row.style.transition = 'all 0.3s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateX(0)';
            }, index * 50 + 300);
        });
    }

    handleButtonClick(e) {
        const btn = e.target.closest('.btn');
        if (!btn) return;

        // Add click effect
        btn.style.transform = 'scale(0.98)';
        setTimeout(() => {
            btn.style.transform = '';
        }, 150);

        // Handle specific button actions
        if (btn.classList.contains('btn-download')) {
            this.handleDownload(btn);
        } else if (btn.classList.contains('btn-delete')) {
            this.handleDelete(btn, e);
        } else if (btn.classList.contains('btn-copy')) {
            this.handleCopy(btn);
        }
    }

    handleFileChange(e) {
        const input = e.target;
        const uploadArea = input.closest('.file-upload');
        const label = uploadArea.querySelector('.file-upload-label');
        const content = label.querySelector('.file-upload-content');

        if (input.files && input.files.length > 0) {
            const file = input.files[0];
            const fileName = file.name;
            const fileSize = this.formatFileSize(file.size);
            const fileIcon = this.getFileIcon(file.type);

            content.innerHTML = `
                <div class="file-selected">
                    <div class="file-icon">${fileIcon}</div>
                    <div class="file-info">
                        <div class="file-name">${fileName}</div>
                        <div class="file-size">${fileSize}</div>
                    </div>
                    <div class="file-status">✓</div>
                </div>
            `;

            // Validate file
            this.validateFile(file, input);
        } else {
            // Reset to default state
            content.innerHTML = `
                <div class="file-upload-icon">+</div>
                <div>
                    <div style="font-weight: 600; margin-bottom: 4px;">Choose a file or drag it here</div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">PDF or TXT files, up to 10MB</div>
                </div>
            `;
        }
    }

    handleSearch(query) {
        const rows = document.querySelectorAll('.table tbody tr');
        const lowercaseQuery = query.toLowerCase();

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const shouldShow = text.includes(lowercaseQuery);

            row.style.display = shouldShow ? '' : 'none';

            if (shouldShow && query) {
                // Highlight matching text
                this.highlightText(row, query);
            } else {
                this.removeHighlight(row);
            }
        });

        // Update empty state
        const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none');
        this.updateEmptyState(visibleRows.length === 0 && query);
    }

    validateForm(form, event) {
        let isValid = true;
        const requiredFields = form.querySelectorAll('[required]');

        requiredFields.forEach(field => {
            if (!this.validateField(field)) {
                isValid = false;
            }
        });

        if (!isValid) {
            event.preventDefault();
            this.hideLoader();
            this.showNotification('Please fill in all required fields', 'error');
        }

        return isValid;
    }

    validateField(field) {
        const value = field.value.trim();
        const fieldType = field.type;
        let isValid = true;
        let errorMessage = '';

        // Required validation
        if (field.hasAttribute('required') && !value) {
            isValid = false;
            errorMessage = 'This field is required';
        }

        // File validation
        if (fieldType === 'file' && field.files && field.files.length > 0) {
            const file = field.files[0];
            const validationResult = this.validateFile(file, field);
            if (!validationResult.isValid) {
                isValid = false;
                errorMessage = validationResult.message;
            }
        }

        // User ID validation
        if (field.name === 'userId' && value) {
            if (!/^[a-f0-9]{32}$/.test(value)) {
                isValid = false;
                errorMessage = 'User ID must be a 32-character hexadecimal string';
            }
        }

        // Show/hide error
        if (isValid) {
            this.clearFieldError(field);
        } else {
            this.showFieldError(field, errorMessage);
        }

        return isValid;
    }

    validateFile(file, input) {
        const maxSize = 10 * 1024 * 1024; // 10MB
        const allowedTypes = ['application/pdf', 'text/plain'];

        if (file.size > maxSize) {
            return {
                isValid: false,
                message: 'File size must be less than 10MB'
            };
        }

        if (!allowedTypes.includes(file.type)) {
            return {
                isValid: false,
                message: 'Only PDF and TXT files are allowed'
            };
        }

        return { isValid: true };
    }

    showFieldError(field, message) {
        this.clearFieldError(field);

        field.classList.add('error');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error';
        errorDiv.textContent = message;

        field.parentNode.appendChild(errorDiv);
    }

    clearFieldError(field) {
        field.classList.remove('error');
        const existingError = field.parentNode.querySelector('.field-error');
        if (existingError) {
            existingError.remove();
        }
    }

    handleDownload(btn) {
        const filename = btn.dataset.file;
        if (!filename) return;

        // Add loading state
        const originalText = btn.innerHTML;
        btn.innerHTML = '<span class="loading"></span> Downloading...';
        btn.disabled = true;

        // Simulate download delay (in real app, this would be the actual download)
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            this.showNotification('Download started', 'success');
        }, 1000);
    }

    handleDelete(btn, event) {
        event.preventDefault();

        const filename = btn.dataset.file;
        if (!filename) return;

        if (confirm(`Are you sure you want to delete ${filename}?`)) {
            // Add loading state
            const row = btn.closest('tr');
            row.style.opacity = '0.5';

            // Simulate delete operation
            setTimeout(() => {
                row.remove();
                this.showNotification('File deleted successfully', 'success');
            }, 500);
        }
    }

    handleCopy(btn) {
        const textToCopy = btn.dataset.copy;
        if (!textToCopy) return;

        navigator.clipboard.writeText(textToCopy).then(() => {
            const originalText = btn.innerHTML;
            btn.innerHTML = '✓ Copied!';

            setTimeout(() => {
                btn.innerHTML = originalText;
            }, 2000);

            this.showNotification('Copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy', 'error');
        });
    }

    showNotification(message, type = 'info') {
        // Remove existing notifications
        document.querySelectorAll('.notification').forEach(n => n.remove());

        const notification = document.createElement('div');
        notification.className = `notification alert alert-${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">×</button>
        `;

        document.body.appendChild(notification);

        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    showLoader() {
        let loader = document.querySelector('.app-loader');
        if (!loader) {
            loader = document.createElement('div');
            loader.className = 'app-loader';
            loader.innerHTML = '<div class="loading"></div>';
            document.body.appendChild(loader);
        }
        loader.style.display = 'flex';
    }

    hideLoader() {
        const loader = document.querySelector('.app-loader');
        if (loader) {
            loader.style.display = 'none';
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    getFileIcon(mimeType) {
        switch (mimeType) {
            case 'application/pdf':
                return 'PDF';
            case 'text/plain':
                return 'TXT';
            default:
                return 'FILE';
        }
    }

    highlightText(element, query) {
        // Simple text highlighting (in production, use a more robust solution)
        const textNodes = this.getTextNodes(element);
        textNodes.forEach(node => {
            const text = node.textContent;
            const regex = new RegExp(`(${query})`, 'gi');
            if (regex.test(text)) {
                const highlightedText = text.replace(regex, '<mark>$1</mark>');
                const wrapper = document.createElement('span');
                wrapper.innerHTML = highlightedText;
                node.parentNode.replaceChild(wrapper, node);
            }
        });
    }

    removeHighlight(element) {
        element.querySelectorAll('mark').forEach(mark => {
            mark.outerHTML = mark.innerHTML;
        });
    }

    getTextNodes(element) {
        const textNodes = [];
        const walker = document.createTreeWalker(
            element,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );

        let node;
        while (node = walker.nextNode()) {
            textNodes.push(node);
        }

        return textNodes;
    }

    updateEmptyState(isEmpty) {
        let emptyState = document.querySelector('.empty-state');

        if (isEmpty && !emptyState) {
            emptyState = document.createElement('div');
            emptyState.className = 'empty-state';
            emptyState.innerHTML = `
                <div class="empty-state-icon">SEARCH</div>
                <h3>No results found</h3>
                <p>Try adjusting your search terms</p>
            `;

            const table = document.querySelector('.table');
            if (table) {
                table.parentNode.appendChild(emptyState);
            }
        } else if (!isEmpty && emptyState) {
            emptyState.remove();
        }
    }

    initDropdowns() {
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            const trigger = dropdown.querySelector('.dropdown-trigger');
            const menu = dropdown.querySelector('.dropdown-menu');

            if (trigger && menu) {
                trigger.addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.toggle('show');
                });
            }
        });

        // Close dropdowns when clicking outside
        document.addEventListener('click', () => {
            document.querySelectorAll('.dropdown-menu.show').forEach(menu => {
                menu.classList.remove('show');
            });
        });
    }

    initModals() {
        document.querySelectorAll('[data-modal]').forEach(trigger => {
            trigger.addEventListener('click', (e) => {
                e.preventDefault();
                const modalId = trigger.dataset.modal;
                const modal = document.getElementById(modalId);
                if (modal) {
                    this.showModal(modal);
                }
            });
        });

        document.querySelectorAll('.modal-close').forEach(closeBtn => {
            closeBtn.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                if (modal) {
                    this.hideModal(modal);
                }
            });
        });
    }

    showModal(modal) {
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';

        setTimeout(() => {
            modal.classList.add('show');
        }, 10);
    }

    hideModal(modal) {
        modal.classList.remove('show');

        setTimeout(() => {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }, 300);
    }

    initTables() {
        document.querySelectorAll('.table').forEach(table => {
            // Add hover effects
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                row.addEventListener('mouseenter', () => {
                    row.style.transform = 'translateX(4px)';
                });

                row.addEventListener('mouseleave', () => {
                    row.style.transform = '';
                });
            });
        });
    }

    initCharts() {
        // Placeholder for chart initialization
        // In a real app, you might use Chart.js or similar
        console.log('Charts initialized');
    }

    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Utility method for debouncing
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

// Additional CSS for dynamic components
const additionalStyles = `
    .loading-spinner {
        display: inline-block;
        width: 12px;
        height: 12px;
        border: 2px solid transparent;
        border-top: 2px solid currentColor;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin-right: 0.5rem;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    .field-error {
        color: var(--error);
        font-size: 0.75rem;
        margin-top: 0.25rem;
    }

    .form-control.error {
        border-color: var(--error);
        box-shadow: 0 0 0 3px rgba(255, 71, 87, 0.1);
    }

    .file-selected {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 1rem;
        background: var(--bg-tertiary);
        border-radius: 8px;
        width: 100%;
    }

    .file-icon {
        font-size: 2rem;
    }

    .file-info {
        flex: 1;
        text-align: left;
    }

    .file-name {
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.25rem;
    }

    .file-size {
        font-size: 0.75rem;
        color: var(--text-muted);
    }

    .file-status {
        color: var(--success);
        font-size: 1.5rem;
    }

    .drag-over {
        border-color: var(--primary-blue) !important;
        background: rgba(0, 102, 255, 0.1) !important;
    }

    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-width: 300px;
        animation: slideIn 0.3s ease;
    }

    .notification-close {
        background: none;
        border: none;
        color: inherit;
        font-size: 1.25rem;
        cursor: pointer;
        padding: 0;
        margin-left: 1rem;
    }

    .app-loader {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(10, 10, 10, 0.8);
        display: none;
        align-items: center;
        justify-content: center;
        z-index: 9999;
        backdrop-filter: blur(4px);
    }

    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    mark {
        background: rgba(0, 102, 255, 0.3);
        color: var(--text-primary);
        padding: 0.125rem 0.25rem;
        border-radius: 3px;
    }
`;

// Inject additional styles
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.finSightApp = new FinSightApp();
});

// Global function for upload form navigation
function handleUploadClick(button) {
    const userIdInput = document.getElementById('userId');
    const userId = userIdInput ? userIdInput.value.trim() : '';

    if (!userId) {
        window.finSightApp.showNotification('Please enter a User ID first', 'error');
        userIdInput.focus();
        return;
    }

    // Validate User ID format
    if (!/^[a-f0-9]{32}$/.test(userId)) {
        window.finSightApp.showNotification('User ID must be a 32-character hexadecimal string', 'error');
        userIdInput.focus();
        return;
    }

    // Show loading state on button
    const originalText = button.innerHTML;
    button.innerHTML = '<span class="loading-spinner"></span> Loading...';
    button.disabled = true;

    // Show loader while navigating
    window.finSightApp.showLoader();

    // Redirect to upload form via direct servlet call
    window.location.href = `statements/upload?userId=${userId}`;
}

function openUploadForm() {
    // Legacy function - redirect to new handler
    const uploadButton = document.querySelector('button[onclick*="openUploadForm"]');
    if (uploadButton) {
        handleUploadClick(uploadButton);
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FinSightApp;
}
