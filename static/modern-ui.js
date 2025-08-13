// Modern UI JavaScript Framework for A&P POR Automator
// Enhanced interactions, sidebar management, and modern UX features

class ModernUI {
    constructor() {
        this.sidebar = document.querySelector('.sidebar');
        this.sidebarToggle = document.querySelector('.sidebar-toggle');
        this.mainContent = document.querySelector('.main-content');
        this.fab = document.querySelector('.fab');
        this.currentPage = this.getCurrentPage();
        
        this.init();
    }
    
    init() {
        this.setupSidebar();
        this.setupFloatingActions();
        this.setupUploadZones();
        this.setupTables();
        this.setupForms();
        this.setupAnimations();
        this.setupResponsive();
        this.highlightCurrentPage();
    }
    
    setupSidebar() {
        if (this.sidebarToggle) {
            this.sidebarToggle.addEventListener('click', () => {
                this.toggleSidebar();
            });
        }
        
        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', (e) => {
            if (window.innerWidth <= 1024 && 
                !this.sidebar.contains(e.target) && 
                !this.sidebarToggle.contains(e.target)) {
                this.closeSidebar();
            }
        });
        
        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeSidebar();
            }
        });
    }
    
    toggleSidebar() {
        this.sidebar.classList.toggle('collapsed');
        this.mainContent.classList.toggle('expanded');
        
        // Store preference
        localStorage.setItem('sidebarCollapsed', this.sidebar.classList.contains('collapsed'));
    }
    
    openSidebar() {
        this.sidebar.classList.remove('collapsed');
        this.mainContent.classList.remove('expanded');
    }
    
    closeSidebar() {
        this.sidebar.classList.add('collapsed');
        this.mainContent.classList.add('expanded');
    }
    
    setupFloatingActions() {
        if (this.fab) {
            this.fab.addEventListener('click', () => {
                this.showQuickActions();
            });
        }
    }
    
    showQuickActions() {
        const actions = [
            { label: 'Upload File', icon: '📁', action: () => window.location.href = '/upload' },
            { label: 'Search PORs', icon: '🔍', action: () => window.location.href = '/search' },
            { label: 'View All', icon: '📋', action: () => window.location.href = '/view' }
        ];
        
        this.createActionMenu(actions);
    }
    
    createActionMenu(actions) {
        // Remove existing menu
        const existingMenu = document.querySelector('.action-menu');
        if (existingMenu) existingMenu.remove();
        
        const menu = document.createElement('div');
        menu.className = 'action-menu';
        menu.style.cssText = `
            position: fixed;
            bottom: 80px;
            right: 32px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1);
            padding: 16px;
            z-index: 1000;
            min-width: 200px;
            transform: scale(0.9);
            opacity: 0;
            transition: all 0.2s ease;
        `;
        
        actions.forEach(action => {
            const button = document.createElement('button');
            button.className = 'action-item';
            button.style.cssText = `
                display: flex;
                align-items: center;
                gap: 12px;
                width: 100%;
                padding: 12px;
                border: none;
                background: none;
                cursor: pointer;
                border-radius: 8px;
                transition: background 0.15s ease;
                font-family: inherit;
                font-size: 14px;
                color: #333;
            `;
            
            button.innerHTML = `
                <span style="font-size: 18px;">${action.icon}</span>
                <span>${action.label}</span>
            `;
            
            button.addEventListener('click', () => {
                action.action();
                this.hideActionMenu();
            });
            
            button.addEventListener('mouseenter', () => {
                button.style.background = '#f8f9fa';
            });
            
            button.addEventListener('mouseleave', () => {
                button.style.background = 'none';
            });
            
            menu.appendChild(button);
        });
        
        document.body.appendChild(menu);
        
        // Animate in
        requestAnimationFrame(() => {
            menu.style.transform = 'scale(1)';
            menu.style.opacity = '1';
        });
        
        // Click outside to close
        setTimeout(() => {
            document.addEventListener('click', this.hideActionMenu.bind(this), { once: true });
        }, 100);
    }
    
    hideActionMenu() {
        const menu = document.querySelector('.action-menu');
        if (menu) {
            menu.style.transform = 'scale(0.9)';
            menu.style.opacity = '0';
            setTimeout(() => menu.remove(), 200);
        }
    }
    
    setupUploadZones() {
        const uploadZones = document.querySelectorAll('.upload-zone');
        
        uploadZones.forEach(zone => {
            const input = zone.querySelector('input[type="file"]');
            if (!input) return;
            
            // Drag and drop
            zone.addEventListener('dragover', (e) => {
                e.preventDefault();
                zone.classList.add('dragover');
            });
            
            zone.addEventListener('dragleave', () => {
                zone.classList.remove('dragover');
            });
            
            zone.addEventListener('drop', (e) => {
                e.preventDefault();
                zone.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    input.files = files;
                    this.handleFileUpload(files[0], zone);
                }
            });
            
            // Click to upload
            zone.addEventListener('click', () => {
                input.click();
            });
            
            // File input change
            input.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    this.handleFileUpload(e.target.files[0], zone);
                }
            });
        });
    }
    
    handleFileUpload(file, zone) {
        // Update zone appearance
        const icon = zone.querySelector('.upload-icon');
        const text = zone.querySelector('.upload-text');
        const hint = zone.querySelector('.upload-hint');
        
        if (icon) icon.textContent = '✅';
        if (text) text.textContent = `File selected: ${file.name}`;
        if (hint) hint.textContent = `Size: ${this.formatFileSize(file.size)}`;
        
        // Add success animation
        zone.style.background = 'linear-gradient(135deg, #4ECDC4 0%, #44A08D 100%)';
        zone.style.color = 'white';
        zone.style.transform = 'scale(1.02)';
        
        setTimeout(() => {
            zone.style.transform = 'scale(1)';
        }, 200);
    }
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    setupTables() {
        const tables = document.querySelectorAll('.table');
        
        tables.forEach(table => {
            // Add sticky header support
            const thead = table.querySelector('thead');
            if (thead) {
                thead.style.position = 'sticky';
                thead.style.top = '0';
                thead.style.zIndex = '10';
            }
            
            // Add row hover effects
            const tbody = table.querySelector('tbody');
            if (tbody) {
                const rows = tbody.querySelectorAll('tr');
                rows.forEach(row => {
                    row.addEventListener('mouseenter', () => {
                        row.style.background = '#f8f9fa';
                        row.style.transform = 'scale(1.01)';
                    });
                    
                    row.addEventListener('mouseleave', () => {
                        row.style.background = '';
                        row.style.transform = 'scale(1)';
                    });
                });
            }
        });
    }
    
    setupForms() {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            const inputs = form.querySelectorAll('input, textarea, select');
            
            inputs.forEach(input => {
                // Add focus effects
                input.addEventListener('focus', () => {
                    input.parentElement.classList.add('focused');
                });
                
                input.addEventListener('blur', () => {
                    input.parentElement.classList.remove('focused');
                });
                
                // Add validation feedback
                input.addEventListener('input', () => {
                    this.validateInput(input);
                });
            });
            
            // Form submission enhancement
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                    this.showFormErrors(form);
                }
            });
        });
    }
    
    validateInput(input) {
        const value = input.value.trim();
        let isValid = true;
        let errorMessage = '';
        
        // Required validation
        if (input.hasAttribute('required') && !value) {
            isValid = false;
            errorMessage = 'This field is required';
        }
        
        // Email validation
        if (input.type === 'email' && value && !this.isValidEmail(value)) {
            isValid = false;
            errorMessage = 'Please enter a valid email address';
        }
        
        // Update input state
        if (isValid) {
            input.classList.remove('error');
            input.classList.add('valid');
            this.removeErrorMessage(input);
        } else {
            input.classList.remove('valid');
            input.classList.add('error');
            this.showErrorMessage(input, errorMessage);
        }
        
        return isValid;
    }
    
    validateForm(form) {
        const inputs = form.querySelectorAll('input, textarea, select');
        let isValid = true;
        
        inputs.forEach(input => {
            if (!this.validateInput(input)) {
                isValid = false;
            }
        });
        
        return isValid;
    }
    
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    showErrorMessage(input, message) {
        this.removeErrorMessage(input);
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            color: #FF6B6B;
            font-size: 12px;
            margin-top: 4px;
            font-weight: 500;
        `;
        
        input.parentElement.appendChild(errorDiv);
    }
    
    removeErrorMessage(input) {
        const existingError = input.parentElement.querySelector('.error-message');
        if (existingError) {
            existingError.remove();
        }
    }
    
    showFormErrors(form) {
        const firstError = form.querySelector('.error');
        if (firstError) {
            firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
            firstError.focus();
        }
    }
    
    setupAnimations() {
        // Intersection Observer for scroll animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, observerOptions);
        
        // Observe elements for animation
        const animateElements = document.querySelectorAll('.card, .table-container, .upload-zone');
        animateElements.forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(20px)';
            el.style.transition = 'all 0.6s ease';
            observer.observe(el);
        });
    }
    
    setupResponsive() {
        // Handle window resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                this.handleResize();
            }, 250);
        });
        
        this.handleResize();
    }
    
    handleResize() {
        if (window.innerWidth <= 1024) {
            this.closeSidebar();
        } else {
            this.openSidebar();
        }
    }
    
    getCurrentPage() {
        const path = window.location.pathname;
        if (path === '/') return 'dashboard';
        if (path === '/upload') return 'upload';
        if (path === '/view') return 'view';
        if (path === '/search') return 'search';
        if (path.includes('/attach')) return 'attach';
        if (path.includes('/change-batch')) return 'change_batch';
        return 'dashboard';
    }
    
    highlightCurrentPage() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            const href = item.getAttribute('href');
            if (href === `/${this.currentPage}` || 
                (this.currentPage === 'dashboard' && href === '/')) {
                item.classList.add('active');
            }
        });
    }
    
    // Utility methods
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            max-width: 300px;
        `;
        
        // Set background based on type
        switch (type) {
            case 'success':
                notification.style.background = 'linear-gradient(135deg, #4ECDC4 0%, #44A08D 100%)';
                break;
            case 'error':
                notification.style.background = 'linear-gradient(135deg, #FF6B6B 0%, #C44569 100%)';
                break;
            case 'warning':
                notification.style.background = 'linear-gradient(135deg, #FFE66D 0%, #FFA726 100%)';
                break;
            default:
                notification.style.background = 'linear-gradient(135deg, #FF6B6B 0%, #4ECDC4 100%)';
        }
        
        notification.textContent = message;
        document.body.appendChild(notification);
        
        // Animate in
        requestAnimationFrame(() => {
            notification.style.transform = 'translateX(0)';
        });
        
        // Auto remove
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }
    
    showLoading(container) {
        const loader = document.createElement('div');
        loader.className = 'loading-spinner';
        loader.innerHTML = `
            <div class="spinner"></div>
            <p>Processing...</p>
        `;
        loader.style.cssText = `
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px;
            color: #6C757D;
        `;
        
        container.appendChild(loader);
        return loader;
    }
    
    hideLoading(loader) {
        if (loader) {
            loader.remove();
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.modernUI = new ModernUI();
    
    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        .animate-in {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
        
        .loading-spinner .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid #E9ECEF;
            border-top: 3px solid #FF6B6B;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 16px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .action-menu {
            animation: slideUp 0.2s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(10px) scale(0.9);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }
        
        .focused .form-input {
            border-color: #4ECDC4;
            box-shadow: 0 0 0 3px rgba(78, 205, 196, 0.1);
        }
        
        .form-input.valid {
            border-color: #4ECDC4;
        }
        
        .form-input.error {
            border-color: #FF6B6B;
        }
    `;
    document.head.appendChild(style);
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ModernUI;
}
