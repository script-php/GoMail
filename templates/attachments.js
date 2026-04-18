// Attachment file handling for compose form

// Keep track of accumulated files
let accumulatedFiles = [];

function handleAttachmentChange(event) {
    const input = event.target;
    
    if (!input.files || input.files.length === 0) {
        return;
    }
    
    // Add newly selected files to accumulated list
    for (let i = 0; i < input.files.length; i++) {
        // Check if file already exists (by name and size)
        const newFile = input.files[i];
        const isDuplicate = accumulatedFiles.some(f => 
            f.name === newFile.name && f.size === newFile.size
        );
        
        if (!isDuplicate) {
            accumulatedFiles.push(newFile);
        }
    }
    
    // Clear the input so user can select more files
    input.value = '';
    
    // Update the display
    updateFileList();
}

function updateFileList() {
    const listDiv = document.getElementById('attachments-list');
    listDiv.innerHTML = '';
    
    if (accumulatedFiles.length === 0) {
        return;
    }
    
    let totalSize = 0;
    for (const file of accumulatedFiles) {
        totalSize += file.size;
    }
    
    // Validate total size
    if (totalSize > 25 * 1024 * 1024) {
        const p = document.createElement('p');
        p.className = 'error-text';
        p.textContent = 'Total attachment size exceeds 25MB limit';
        listDiv.appendChild(p);
        return;
    }
    
    // Validate file count
    if (accumulatedFiles.length > 10) {
        const p = document.createElement('p');
        p.className = 'error-text';
        p.textContent = 'Maximum 10 attachments allowed';
        listDiv.appendChild(p);
        return;
    }
    
    // Display each file with remove button
    const ul = document.createElement('ul');
    ul.className = 'attachments-list-items';
    
    for (let i = 0; i < accumulatedFiles.length; i++) {
        const file = accumulatedFiles[i];
        const li = document.createElement('li');
        li.className = 'attachment-item';
        
        const sizeKB = (file.size / 1024).toFixed(1);
        const fileName = file.name
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
        
        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'attachment-remove';
        removeBtn.textContent = '✕';
        removeBtn.addEventListener('click', function(e) {
            e.preventDefault();
            accumulatedFiles.splice(i, 1);
            updateFileList();
        });
        
        li.innerHTML = `
            <span class="attachment-name">${fileName}</span>
            <span class="attachment-size">${sizeKB} KB</span>
        `;
        li.appendChild(removeBtn);
        
        ul.appendChild(li);
    }
    
    listDiv.appendChild(ul);
    
    // Show summary
    const p = document.createElement('p');
    p.className = 'attachments-summary';
    p.textContent = `${accumulatedFiles.length} file(s) selected (${(totalSize / 1024).toFixed(1)} KB total)`;
    listDiv.appendChild(p);
}

// Initialize attachment handlers when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const attachBtn = document.getElementById('attachments-btn');
    const attachInput = document.getElementById('attachments');
    
    if (attachBtn) {
        attachBtn.addEventListener('click', function(e) {
            e.preventDefault();
            attachInput.click();
        });
    }
    
    if (attachInput) {
        attachInput.addEventListener('change', handleAttachmentChange);
    }
});

// Set accumulated files to the file input before form submission
// This is needed so the files are submitted with the form
document.addEventListener('submit', function(e) {
    if (e.target && e.target.id === 'compose-form' && accumulatedFiles.length > 0) {
        const attachInput = document.getElementById('attachments');
        if (attachInput && window.DataTransfer) {
            try {
                const dt = new DataTransfer();
                for (const file of accumulatedFiles) {
                    dt.items.add(file);
                }
                attachInput.files = dt.files;
            } catch (err) {
                console.warn('Could not set files for submission:', err);
            }
        }
    }
}, true);

