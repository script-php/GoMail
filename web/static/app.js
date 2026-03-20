// GoMail - Minimal client-side JavaScript

// Toggle star on a message
function toggleStar(messageId, event) {
    event.preventDefault();
    event.stopPropagation();

    fetch('/message/star/' + messageId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(r => r.json())
    .then(data => {
        const btn = event.target;
        if (data.starred) {
            btn.classList.add('starred');
            btn.innerHTML = '&#9733;';
        } else {
            btn.classList.remove('starred');
            btn.innerHTML = '&#9734;';
        }
    })
    .catch(err => console.error('Star toggle failed:', err));
}

// Mark message as read via AJAX
function markRead(messageId) {
    fetch('/api/mark-read/' + messageId, {
        method: 'POST'
    }).catch(err => console.error('Mark read failed:', err));
}

// Poll for unread count every 30 seconds
function pollUnread() {
    fetch('/api/unread-count')
        .then(r => r.json())
        .then(data => {
            const badges = document.querySelectorAll('.badge');
            badges.forEach(badge => {
                if (data.unread > 0) {
                    badge.textContent = data.unread;
                    badge.style.display = 'inline';
                } else {
                    badge.style.display = 'none';
                }
            });
        })
        .catch(() => {}); // Silently fail
}

// Auto-refresh unread count
if (document.querySelector('.sidebar')) {
    setInterval(pollUnread, 30000);
}

// Click row to navigate to message
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.message-row').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function(e) {
            // Don't navigate if clicking star button
            if (e.target.classList.contains('star-btn')) return;
            if (e.target.tagName === 'A') return;

            const id = this.dataset.id;
            window.location.href = '/message/' + id;
        });
    });
});
