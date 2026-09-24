// ===== UTILITY FUNCTIONS =====
function copyToClipboard(text) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
        return Promise.reject(new Error('Clipboard requires a secure connection. Select and copy the value manually.'));
    }
    return navigator.clipboard.writeText(text);
}
function csrfHeaders() {
    var token = document.querySelector('meta[name="csrf-token"]');
    return { 'Content-Type': 'application/json', 'X-CSRF-Token': token ? token.content : '' };
}
function checkedResponse(response) {
    if (!response.ok || response.redirected) throw new Error('Action failed. Please refresh the page and try again.');
    return response.json();
}
function showMailError(error) {
    var box = document.getElementById('mail-action-error');
    if (box) { box.hidden = false; box.textContent = error.message; }
    else { window.alert(error.message); }
}
function updateSelection() {
    var boxes = Array.from(document.querySelectorAll('.email-row input[type="checkbox"]'));
    var count = boxes.filter(function(cb) { return cb.checked; }).length;
    var master = document.getElementById('select-all');
    if (master) { master.checked = count > 0 && count === boxes.length; master.indeterminate = count > 0 && count < boxes.length; }
    var label = document.getElementById('selection-count');
    if (label) label.textContent = count ? count + ' selected' : '';
    document.querySelectorAll('[data-bulk-action], #move-folder').forEach(function(el) { el.disabled = !count; });
}
function bulkAction(action, folderID) {
    var ids = Array.from(document.querySelectorAll('.email-row input:checked')).map(function(cb) { return Number(cb.closest('.email-row').dataset.id); });
    if (!ids.length) return;
    var trigger = document.querySelector('[data-bulk-action="' + action + '"]');
    if (trigger && trigger.dataset.confirmBulk && !window.confirm(trigger.dataset.confirmBulk)) return;
    document.querySelectorAll('[data-bulk-action], #move-folder').forEach(function(el) { el.disabled = true; });
    fetch('/api/messages/action', { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ ids: ids, action: action, folder_id: Number(folderID || 0) }) })
        .then(checkedResponse).then(function() { location.reload(); })
        .catch(function(error) { showMailError(error); updateSelection(); });
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
        headers: csrfHeaders()
    })
    .then(checkedResponse)
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
    .catch(showMailError);
}

// ===== CHECKBOX: SELECT ALL =====
function toggleAllCheckboxes(masterCb) {
    var checkboxes = document.querySelectorAll('.email-row .email-checkbox input[type="checkbox"]');
    checkboxes.forEach(function(cb) { cb.checked = masterCb.checked; });
    updateSelection();
}

// ===== MARK READ =====
function markRead(messageId) {
    fetch('/api/mark-read/' + messageId, { method: 'POST', headers: csrfHeaders() }).then(checkedResponse)
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
        .then(checkedResponse)
        .then(function(data) {
            document.querySelectorAll('[data-folder-count]').forEach(function(badge) {
                var count = data.folders && data.folders[badge.dataset.folderCount];
                if (typeof count === 'number') { badge.textContent = count; badge.hidden = count === 0; }
            });
            var badges = document.querySelectorAll('.nav-links .badge:not([data-folder-count])');
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
	var composeForm=document.getElementById('compose-form');
	if(composeForm){
		var draftStatus=document.getElementById('draft-status'), draftTimer, draftDirty=false;
		function saveDraft(){if(!draftDirty)return Promise.resolve();var data=new URLSearchParams();['draft_id','to','cc','subject','body'].forEach(function(id){data.set(id,document.getElementById(id).value)});data.set('csrf_token',composeForm.elements.csrf_token.value);draftStatus.textContent='Saving…';return fetch('/api/drafts',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:data}).then(function(r){if(!r.ok)throw new Error();return r.json()}).then(function(v){document.getElementById('draft_id').value=v.id;draftDirty=false;draftStatus.textContent='Draft saved';}).catch(function(){draftStatus.textContent='Draft could not be saved';});}
		['to','cc','subject','body'].forEach(function(id){document.getElementById(id).addEventListener('input',function(){draftDirty=true;clearTimeout(draftTimer);draftTimer=setTimeout(saveDraft,1500)})});
		document.getElementById('save-draft').addEventListener('click',function(){draftDirty=true;saveDraft()});composeForm.addEventListener('submit',function(){draftDirty=false;clearTimeout(draftTimer)});
	}
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
    var masterCheckbox = document.getElementById('select-all');
    if (masterCheckbox) {
        masterCheckbox.addEventListener('change', function() {
            toggleAllCheckboxes(this);
        });
    }

    document.querySelectorAll('[data-bulk-action]').forEach(function(btn) {
        btn.addEventListener('click', function() { bulkAction(btn.dataset.bulkAction); });
    });
    var moveFolder = document.getElementById('move-folder');
    if (moveFolder) moveFolder.addEventListener('change', function() {
        if (this.value) bulkAction('move', this.value);
    });

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
        cb.addEventListener('change', updateSelection);
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
			if (id) window.location.href = row.dataset.draft === 'true' ? '/compose?draft=' + id : '/message/' + id;
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
            var originalText = btn.textContent;
            copyToClipboard(text).then(function() {
                btn.textContent = 'Copied!';
                setTimeout(function() { btn.textContent = originalText; }, 2000);
            }).catch(showMailError);
        });
    });

    // Start polling if sidebar exists (logged in)
    if (document.querySelector('.sidebar')) {
        setInterval(pollUnread, 30000);
    }
});
