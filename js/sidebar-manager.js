function generateSidebarHTML(currentPage = 'index') {
    if (typeof SIDEBAR_CONFIG === 'undefined') {
        console.error('SIDEBAR_CONFIG not loaded. Make sure to include sidebar-config.js first.');
        return '';
    }

    let html = '';
    
    SIDEBAR_CONFIG.forEach(item => {
        const linkTarget = currentPage === 'index' ? '#' : 'index.html';
        html += `<li><a href="${linkTarget}" data-md="${item.path}">${item.title}</a></li>\n`;
    });
    
    return html;
}


function initializeSidebar(currentPage = 'index') {
    const sidebarList = document.getElementById('md-list');
    if (!sidebarList) {
        console.error('Sidebar list element not found');
        return;
    }
    
    sidebarList.innerHTML = generateSidebarHTML(currentPage);
    
    if (currentPage === 'index') {
        sidebarList.addEventListener('click', function(e) {
            if (e.target.tagName === 'A' && e.target.dataset.md) {
                e.preventDefault();
                if (typeof loadMarkdown === 'function') {
                    loadMarkdown(e.target.dataset.md);
                    // Highlight active link
                    Array.from(this.querySelectorAll('a')).forEach(a => a.classList.remove('active'));
                    e.target.classList.add('active');
                }
            }
        });
    }
}

function getAllMarkdownFiles() {
    if (typeof SIDEBAR_CONFIG === 'undefined') {
        console.error('SIDEBAR_CONFIG not loaded');
        return [];
    }
    
    return SIDEBAR_CONFIG.map(item => ({
        title: item.title,
        path: item.path
    }));
}


document.addEventListener('DOMContentLoaded', function() {
    const currentPage = window.location.pathname.includes('index.html') || 
                       window.location.pathname.endsWith('/') || 
                       window.location.pathname === '' ? 'index' : 'other';
    
    initializeSidebar(currentPage);
    
    if (currentPage === 'index') {
        const firstLink = document.querySelector('#md-list a[data-md]');
        if (firstLink && typeof loadMarkdown === 'function') {
            firstLink.classList.add('active');
            loadMarkdown(firstLink.getAttribute('data-md'));
        }
    }
});

if (typeof window !== 'undefined') {
    window.SidebarManager = {
        generateSidebarHTML,
        initializeSidebar,
        getAllMarkdownFiles
    };
}
