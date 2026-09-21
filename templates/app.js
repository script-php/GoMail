// ===== UTILITY FUNCTIONS =====
function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function(err) {
            console.error('Failed to copy:', err);
        });
    }
}
function toggleSidebar() {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.querySelector('.sidebar-overlay');
    if (sidebar) {
        sidebar.classList.toggle('open');
        if (overlay) overlay.classList.toggle('active');
    }
}

function closeSidebar() {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.querySelector('.sidebar-overlay');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
}

// Close sidebar on ESC
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeSidebar();
});

// ===== STAR TOGGLE =====
function toggleStar(messageId, event) {
    event.preventDefault();
    event.stopPropagation();

    fetch('/message/star/' + messageId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        var btn = event.target.closest('.star-btn') || event.target;
        if (data.starred) {
            btn.classList.add('starred');
            btn.innerHTML = '&#9733;';
        } else {
            btn.classList.remove('starred');
            btn.innerHTML = '&#9734;';
        }
    })
    .catch(function(err) { console.error('Star toggle failed:', err); });
}

// ===== CHECKBOX: SELECT ALL =====
function toggleAllCheckboxes(masterCb) {
    var checkboxes = document.querySelectorAll('.email-row .email-checkbox input[type="checkbox"]');
    checkboxes.forEach(function(cb) { cb.checked = masterCb.checked; });
}

// ===== MARK READ =====
function markRead(messageId) {
    fetch('/api/mark-read/' + messageId, { method: 'POST' })
        .catch(function(err) { console.error('Mark read failed:', err); });
}

// ===== MDN DISMISS =====
function dismissMDNNotice(messageId) {
    var notices = document.querySelectorAll('.mdn-notice');
    notices.forEach(function(n) { n.style.display = 'none'; });
}

// ===== POLL UNREAD COUNT =====
function pollUnread() {
    fetch('/api/unread-count')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var badges = document.querySelectorAll('.nav-links .badge');
            badges.forEach(function(badge) {
                var li = badge.closest('li');
                if (li && li.querySelector('a[href="/inbox"], a[href*="inbox"]')) {
                    if (data.unread > 0) {
                        badge.textContent = data.unread;
                        badge.style.display = '';
                    } else {
                        badge.style.display = 'none';
                    }
                }
            });
        })
        .catch(function() {}); // Silently fail
}

// ===== EVENT LISTENERS (DOMContentLoaded) =====
document.addEventListener('DOMContentLoaded', function() {
    // Menu toggle button
    var menuToggle = document.querySelector('.menu-toggle');
    if (menuToggle) {
        menuToggle.addEventListener('click', toggleSidebar);
    }

    // Sidebar overlay click to close
    var sidebarOverlay = document.querySelector('.sidebar-overlay');
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }

    // Master checkbox for select all
    var masterCheckbox = document.querySelector('.email-list .toolbar-left input[type="checkbox"]');
    if (masterCheckbox) {
        masterCheckbox.addEventListener('change', function() {
            toggleAllCheckboxes(this);
        });
    }

    // Refresh button
    var refreshBtn = document.querySelector('.toolbar-btn[title="Refresh"]');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            location.reload();
        });
    }

    // Star buttons
    document.querySelectorAll('.star-btn').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            var messageId = btn.closest('.email-row').dataset.id;
            if (messageId) toggleStar(messageId, e);
        });
    });

    // Checkboxes (stop propagation)
    document.querySelectorAll('.email-row .email-checkbox input[type="checkbox"]').forEach(function(cb) {
        cb.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    });

    // Make email rows clickable
    document.querySelectorAll('.email-row').forEach(function(row) {
        row.addEventListener('click', function(e) {
            // Don't navigate if clicking star, checkbox, or link
            if (e.target.classList.contains('star-btn')) return;
            if (e.target.closest('.star-btn')) return;
            if (e.target.type === 'checkbox') return;
            if (e.target.tagName === 'A') return;

            var id = this.dataset.id;
            if (id) window.location.href = '/message/' + id;
        });
    });

    // MDN deny buttons
    document.querySelectorAll('button[data-dismiss-mdn]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var messageId = btn.dataset.dismissMdn;
            dismissMDNNotice(messageId);
        });
    });

    // Form submissions with confirmation
    document.querySelectorAll('form[data-confirm-delete]').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            var msg = form.dataset.confirmDelete;
            if (!confirm(msg)) {
                e.preventDefault();
            }
        });
    });

    // Delete confirmation buttons
    document.querySelectorAll('button[data-confirm-delete]').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            var msg = btn.dataset.confirmDelete;
            if (!confirm(msg)) {
                e.preventDefault();
            }
        });
    });

    // Refresh page buttons
    document.querySelectorAll('button[data-reload]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            location.reload();
        });
    });

    // Copy buttons
    document.querySelectorAll('button[data-copy-value]').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            var text = btn.dataset.copyValue;
            copyToClipboard(text);
            // Optional: show feedback
            var originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() {
                btn.textContent = originalText;
            }, 2000);
        });
    });

    // Start polling if sidebar exists (logged in)
    if (document.querySelector('.sidebar')) {
        setInterval(pollUnread, 30000);
    }
});
